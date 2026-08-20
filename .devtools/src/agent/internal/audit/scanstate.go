package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

type scanFingerprint struct {
	Size             int64  `json:"size"`
	ModifiedUnixNano int64  `json:"modified_unix_nano"`
	ContentDigest    string `json:"content_digest"`
}

type scanCursor struct {
	Fingerprint     scanFingerprint `json:"fingerprint"`
	NextLine        int             `json:"next_line"`
	PrefixLines     int64           `json:"prefix_lines"`
	IntegrityDigest string          `json:"integrity_digest"`
}

type scannedFileIdentity struct {
	Fingerprint   scanFingerprint
	PhysicalLines int64
}

type authoritativeFingerprint struct {
	Size             int64  `json:"size"`
	ModifiedUnixNano int64  `json:"modified_unix_nano"`
	ContentDigest    string `json:"content_digest"`
}

type providerScanState struct {
	Version            int                                 `json:"version"`
	AuthoritativeFiles map[string]authoritativeFingerprint `json:"authoritative_files"`
	Files              map[string]scanFingerprint          `json:"files"`
	Cursors            map[string]scanCursor               `json:"cursors"`
	HistoryAliases     map[string]string                   `json:"history_aliases"`
}

const (
	currentProviderScanStateVersion = 6
	maxHistoryAliases               = 100_000
	maxScanStateBytes               = 16 * 1024 * 1024
)

func scanStatePath(repoRoot, provider string) string {
	return filepath.Join(localStoreDir(repoRoot), ".scan-state-"+provider+".json")
}

func loadProviderScanState(repoRoot, provider string) (providerScanState, error) {
	state := providerScanState{
		Version:            currentProviderScanStateVersion,
		AuthoritativeFiles: map[string]authoritativeFingerprint{},
		Files:              map[string]scanFingerprint{},
		Cursors:            map[string]scanCursor{},
		HistoryAliases:     map[string]string{},
	}
	path := scanStatePath(repoRoot, provider)
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, fmt.Errorf("read %s scan state: %w", provider, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxScanStateBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return state, fmt.Errorf("read %s scan state: %w", provider, readErr)
	}
	if closeErr != nil {
		return state, fmt.Errorf("close %s scan state: %w", provider, closeErr)
	}
	if len(data) > maxScanStateBytes {
		return state, fmt.Errorf("%s scan state exceeds 16 MiB", provider)
	}
	decodeErr := validateUniqueJSONKeys(data)
	if decodeErr == nil {
		decodeErr = json.Unmarshal(data, &state)
	}
	if decodeErr == nil && (state.Version == 3 || state.Version == 4) &&
		state.Files != nil && state.AuthoritativeFiles != nil {
		// Versions 3 and 4 did not authenticate completed transcripts or the
		// authoritative store using full content. Conservatively rebuild both.
		state.Version = currentProviderScanStateVersion
		state.AuthoritativeFiles = map[string]authoritativeFingerprint{}
		state.Files = map[string]scanFingerprint{}
		state.Cursors = map[string]scanCursor{}
		state.HistoryAliases = map[string]string{}
		return state, nil
	}
	if decodeErr == nil && state.Version == 5 &&
		state.Files != nil && state.AuthoritativeFiles != nil && state.Cursors != nil {
		// Version 5 already authenticated full contents but did not persist
		// one-to-one aliases for legacy history IDs.
		state.Version = currentProviderScanStateVersion
		state.HistoryAliases = map[string]string{}
	}
	valid := decodeErr == nil &&
		state.Version == currentProviderScanStateVersion &&
		state.Files != nil &&
		state.AuthoritativeFiles != nil &&
		state.Cursors != nil &&
		state.HistoryAliases != nil &&
		len(state.HistoryAliases) <= maxHistoryAliases
	if valid {
		for _, fingerprint := range state.AuthoritativeFiles {
			if !validAuthoritativeFingerprint(fingerprint) {
				valid = false
				break
			}
		}
	}
	if valid {
		for _, fingerprint := range state.Files {
			if !validScanFingerprint(fingerprint) {
				valid = false
				break
			}
		}
	}
	if valid {
		for key, cursor := range state.Cursors {
			if cursor.NextLine < 2 ||
				!validScanFingerprint(cursor.Fingerprint) ||
				cursor.PrefixLines < int64(cursor.NextLine) ||
				cursor.IntegrityDigest != scanCursorIntegrityDigest(key, cursor) {
				valid = false
				break
			}
		}
	}
	if valid {
		targets := make(map[string]struct{}, len(state.HistoryAliases))
		for eventID, targetID := range state.HistoryAliases {
			_, duplicateTarget := targets[targetID]
			if !isHistoryEventID(eventID) ||
				!isHistoryEventID(targetID) ||
				len(eventID) > 128 ||
				len(targetID) > 128 ||
				eventID == targetID ||
				duplicateTarget {
				valid = false
				break
			}
			targets[targetID] = struct{}{}
		}
	}
	if !valid {
		quarantine := fmt.Sprintf("%s.stale-%d", path, time.Now().UTC().UnixNano())
		if renameErr := os.Rename(path, quarantine); renameErr != nil {
			return providerScanState{}, fmt.Errorf("quarantine invalid %s scan state: %w", provider, renameErr)
		}
		if err := protectFile(repoRoot, quarantine); err != nil {
			return providerScanState{}, err
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return providerScanState{}, fmt.Errorf("sync invalid %s scan-state quarantine: %w", provider, err)
		}
		recordLocalHealth(repoRoot, "invalid prompt scan state quarantined and rebuilt")
		return providerScanState{
			Version:            currentProviderScanStateVersion,
			AuthoritativeFiles: map[string]authoritativeFingerprint{},
			Files:              map[string]scanFingerprint{},
			Cursors:            map[string]scanCursor{},
			HistoryAliases:     map[string]string{},
		}, nil
	}
	return state, nil
}

func saveProviderScanState(repoRoot, provider string, state providerScanState) error {
	if err := validateDirectoryTree(repoRoot, localStoreDir(repoRoot)); err != nil {
		return err
	}
	if err := ensureDirectoryDurableUnder(repoRoot, localStoreDir(repoRoot), 0o700); err != nil {
		return err
	}
	state.Version = currentProviderScanStateVersion
	if state.Files == nil {
		state.Files = map[string]scanFingerprint{}
	}
	if state.AuthoritativeFiles == nil {
		state.AuthoritativeFiles = map[string]authoritativeFingerprint{}
	}
	if state.Cursors == nil {
		state.Cursors = map[string]scanCursor{}
	}
	if state.HistoryAliases == nil {
		state.HistoryAliases = map[string]string{}
	}
	if len(state.HistoryAliases) > maxHistoryAliases {
		return fmt.Errorf(
			"%s scan state has %d history aliases; maximum is %d",
			provider,
			len(state.HistoryAliases),
			maxHistoryAliases,
		)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode %s scan state: %w", provider, err)
	}
	if len(data) > maxScanStateBytes {
		return fmt.Errorf("%s scan state exceeds 16 MiB", provider)
	}
	path := scanStatePath(repoRoot, provider)
	tmp, err := os.CreateTemp(localStoreDir(repoRoot), ".scan-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create %s scan state: %w", provider, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(append(data, '\n')); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return fmt.Errorf("write %s scan state: %w", provider, err)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s scan state: %w", provider, closeErr)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := replaceFile(tmpName, path); err != nil {
		return fmt.Errorf("replace %s scan state: %w", provider, err)
	}
	if err := protectFile(repoRoot, path); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync %s scan-state directory: %w", provider, err)
	}
	return nil
}

func authoritativeFileState(repoRoot string) (map[string]authoritativeFingerprint, error) {
	current, _, err := authoritativeFileStateExtending(repoRoot, nil)
	return current, err
}

// authoritativeFileStateExtending authenticates each full file and the
// previously trusted prefix in one read from one handle while holding that
// user's capture lock. An append after the lock is released is harmless: the
// returned file remains an authenticated prefix of the newer store.
func authoritativeFileStateExtending(
	repoRoot string,
	previous map[string]authoritativeFingerprint,
) (map[string]authoritativeFingerprint, bool, error) {
	entries, err := os.ReadDir(localStoreDir(repoRoot))
	if errors.Is(err, os.ErrNotExist) {
		entries = nil
	} else if err != nil {
		return nil, false, fmt.Errorf("read authoritative set: %w", err)
	}
	current := make(map[string]authoritativeFingerprint)
	extends := true
	observed := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), registryFileExt) {
			name := entry.Name()
			path := filepath.Join(localStoreDir(repoRoot), name)
			userID := strings.TrimSuffix(name, registryFileExt)
			old, expected := previous[name]
			boundaryEnd := int64(-1)
			if expected {
				observed[name] = struct{}{}
				if validAuthoritativeFingerprint(old) {
					boundaryEnd = old.Size
				} else {
					extends = false
				}
			}
			var full scannedFileIdentity
			var boundary scannedFileIdentity
			var boundaryAvailable bool
			var stable bool
			identityErr := withFileLock(
				localStoreCaptureLockPath(repoRoot, userID),
				localCaptureLockTimeout,
				func() error {
					var err error
					full, boundary, boundaryAvailable, stable, err =
						stableFileIdentities(path, boundaryEnd)
					return err
				},
			)
			if identityErr != nil {
				return nil, false, fmt.Errorf(
					"authenticate authoritative backup %s: %w",
					name,
					identityErr,
				)
			}
			if !stable {
				return nil, false, fmt.Errorf(
					"authenticate authoritative backup %s: file changed while reading",
					name,
				)
			}
			current[name] = authoritativeFingerprint{
				Size:             full.Fingerprint.Size,
				ModifiedUnixNano: full.Fingerprint.ModifiedUnixNano,
				ContentDigest:    full.Fingerprint.ContentDigest,
			}
			if expected &&
				(!validAuthoritativeFingerprint(old) ||
					!boundaryAvailable ||
					full.Fingerprint.Size < old.Size ||
					boundary.Fingerprint.Size != old.Size ||
					boundary.Fingerprint.ContentDigest != old.ContentDigest) {
				extends = false
			}
		}
	}
	for name := range previous {
		if _, exists := observed[name]; !exists {
			extends = false
		}
	}
	return current, extends, nil
}

type fileContentTracker struct {
	hasher    hash.Hash
	size      int64
	newlines  int64
	finalByte byte
}

func newFileContentTracker() *fileContentTracker {
	return &fileContentTracker{hasher: sha256.New()}
}

func (tracker *fileContentTracker) Write(content []byte) (int, error) {
	if int64(len(content)) > int64(^uint64(0)>>1)-tracker.size {
		return 0, errors.New("provider transcript size overflow")
	}
	written, err := tracker.hasher.Write(content)
	if written > 0 {
		accepted := content[:written]
		tracker.size += int64(written)
		tracker.newlines += int64(bytes.Count(accepted, []byte{'\n'}))
		tracker.finalByte = accepted[written-1]
	}
	return written, err
}

func (tracker *fileContentTracker) identity(
	expectedSize int64,
	modified time.Time,
) (scannedFileIdentity, error) {
	if expectedSize < 0 {
		return scannedFileIdentity{}, errors.New("provider transcript has negative size")
	}
	if tracker.size != expectedSize {
		return scannedFileIdentity{}, fmt.Errorf(
			"provider transcript snapshot read %d bytes, want %d",
			tracker.size,
			expectedSize,
		)
	}
	lines := tracker.newlines
	if tracker.size != 0 && tracker.finalByte != '\n' {
		lines++
	}
	return scannedFileIdentity{
		Fingerprint: scanFingerprint{
			Size:             tracker.size,
			ModifiedUnixNano: modified.UnixNano(),
			ContentDigest:    hex.EncodeToString(tracker.hasher.Sum(nil)),
		},
		PhysicalLines: lines,
	}, nil
}

func beginProviderFileSnapshot(
	file *os.File,
) (io.Reader, *fileContentTracker, os.FileInfo, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return nil, nil, nil, errors.New("provider transcript is not a regular file")
	}
	tracker := newFileContentTracker()
	reader := io.TeeReader(io.NewSectionReader(file, 0, info.Size()), tracker)
	return reader, tracker, info, nil
}

func finishProviderFileSnapshot(
	tracker *fileContentTracker,
	info os.FileInfo,
) (scannedFileIdentity, error) {
	if tracker == nil || info == nil {
		return scannedFileIdentity{}, errors.New("provider transcript snapshot is unavailable")
	}
	return tracker.identity(info.Size(), info.ModTime())
}

func digestOpenFilePrefix(
	file *os.File,
	info os.FileInfo,
	end,
	boundaryEnd int64,
) (scannedFileIdentity, scannedFileIdentity, error) {
	if end < 0 || boundaryEnd < -1 || boundaryEnd > end {
		return scannedFileIdentity{}, scannedFileIdentity{},
			errors.New("invalid provider transcript digest boundary")
	}
	full := newFileContentTracker()
	var boundary *fileContentTracker
	if boundaryEnd >= 0 {
		boundary = newFileContentTracker()
	}
	reader := io.NewSectionReader(file, 0, end)
	buffer := make([]byte, 64*1024)
	for full.size < end {
		limit := int64(len(buffer))
		if remaining := end - full.size; remaining < limit {
			limit = remaining
		}
		read, readErr := reader.Read(buffer[:limit])
		if read > 0 {
			chunk := buffer[:read]
			if _, err := full.Write(chunk); err != nil {
				return scannedFileIdentity{}, scannedFileIdentity{}, err
			}
			if boundary != nil && boundary.size < boundaryEnd {
				boundaryRead := int64(read)
				if remaining := boundaryEnd - boundary.size; remaining < boundaryRead {
					boundaryRead = remaining
				}
				if _, err := boundary.Write(chunk[:boundaryRead]); err != nil {
					return scannedFileIdentity{}, scannedFileIdentity{}, err
				}
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return scannedFileIdentity{}, scannedFileIdentity{}, readErr
			}
			break
		}
		if read == 0 {
			return scannedFileIdentity{}, scannedFileIdentity{}, io.ErrNoProgress
		}
	}
	fullIdentity, err := full.identity(end, info.ModTime())
	if err != nil {
		return scannedFileIdentity{}, scannedFileIdentity{}, err
	}
	var boundaryIdentity scannedFileIdentity
	if boundary != nil {
		boundaryIdentity, err = boundary.identity(boundaryEnd, info.ModTime())
		if err != nil {
			return scannedFileIdentity{}, scannedFileIdentity{}, err
		}
	}
	return fullIdentity, boundaryIdentity, nil
}

func filePrefixIdentity(path string, end int64) (scannedFileIdentity, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return scannedFileIdentity{}, fmt.Errorf("read file prefix: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return scannedFileIdentity{}, fmt.Errorf("stat file prefix: %w", err)
	}
	identity, _, digestErr := digestOpenFilePrefix(file, info, end, -1)
	closeErr := file.Close()
	if digestErr != nil {
		return scannedFileIdentity{}, fmt.Errorf("digest file prefix: %w", digestErr)
	}
	if closeErr != nil {
		return scannedFileIdentity{}, fmt.Errorf("close file prefix: %w", closeErr)
	}
	return identity, nil
}

func invalidateScanStateIfStoreSetChanged(repoRoot string, state *providerScanState) error {
	current, extends, err := authoritativeFileStateExtending(
		repoRoot,
		state.AuthoritativeFiles,
	)
	if err != nil {
		return err
	}
	if !extends {
		state.Files = map[string]scanFingerprint{}
		state.Cursors = map[string]scanCursor{}
		state.HistoryAliases = map[string]string{}
	}
	state.AuthoritativeFiles = current
	return nil
}

func validAuthoritativeFingerprint(fingerprint authoritativeFingerprint) bool {
	if fingerprint.Size < 0 || len(fingerprint.ContentDigest) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(fingerprint.ContentDigest)
	return err == nil
}

func authoritativeSetExtends(
	repoRoot string,
	previous,
	current map[string]authoritativeFingerprint,
) (bool, error) {
	for name, old := range previous {
		candidate, exists := current[name]
		if !exists || !validAuthoritativeFingerprint(old) ||
			!validAuthoritativeFingerprint(candidate) ||
			candidate.Size < old.Size {
			return false, nil
		}
		path := filepath.Join(localStoreDir(repoRoot), name)
		userID := strings.TrimSuffix(name, registryFileExt)
		var full scannedFileIdentity
		var prefix scannedFileIdentity
		var stable bool
		err := withFileLock(
			localStoreCaptureLockPath(repoRoot, userID),
			localCaptureLockTimeout,
			func() error {
				var err error
				full, prefix, stable, err = stableFilePrefixIdentities(
					path,
					candidate.Size,
					old.Size,
				)
				return err
			},
		)
		if err != nil {
			return false, err
		}
		if !stable ||
			full.Fingerprint.Size != candidate.Size ||
			full.Fingerprint.ContentDigest != candidate.ContentDigest ||
			prefix.Fingerprint.Size != old.Size ||
			prefix.Fingerprint.ContentDigest != old.ContentDigest {
			return false, nil
		}
	}
	return true, nil
}

func cloneAuthoritativeFileState(
	source map[string]authoritativeFingerprint,
) map[string]authoritativeFingerprint {
	cloned := make(map[string]authoritativeFingerprint, len(source))
	for name, fingerprint := range source {
		cloned[name] = fingerprint
	}
	return cloned
}

func pruneHistoryAliases(
	state *providerScanState,
	existing []model.Event,
	reservedExact map[string]bool,
) bool {
	if state == nil || len(state.HistoryAliases) == 0 {
		return false
	}
	durable := make(map[string]struct{}, len(existing))
	for _, event := range existing {
		durable[event.EventID] = struct{}{}
	}
	requiresRescan := false
	for eventID, targetID := range state.HistoryAliases {
		_, aliasAlreadyDurable := durable[eventID]
		_, targetStillDurable := durable[targetID]
		if aliasAlreadyDurable || !targetStillDurable || reservedExact[targetID] {
			delete(state.HistoryAliases, eventID)
			if !aliasAlreadyDurable {
				requiresRescan = true
			}
		}
	}
	return requiresRescan
}

func mergeHistoryAliases(state *providerScanState, aliases map[string]string) error {
	if state == nil || len(aliases) == 0 {
		return nil
	}
	if state.HistoryAliases == nil {
		state.HistoryAliases = map[string]string{}
	}
	usedTargets := make(map[string]struct{}, len(state.HistoryAliases)+len(aliases))
	for _, targetID := range state.HistoryAliases {
		usedTargets[targetID] = struct{}{}
	}
	for eventID, targetID := range aliases {
		_, duplicateTarget := usedTargets[targetID]
		if !isHistoryEventID(eventID) ||
			!isHistoryEventID(targetID) ||
			len(eventID) > 128 ||
			len(targetID) > 128 ||
			eventID == targetID ||
			duplicateTarget {
			return errors.New("refuse to persist an invalid history alias")
		}
		state.HistoryAliases[eventID] = targetID
		usedTargets[targetID] = struct{}{}
		if len(state.HistoryAliases) > maxHistoryAliases {
			return fmt.Errorf(
				"history alias limit exceeded (%d)",
				maxHistoryAliases,
			)
		}
	}
	return nil
}

func canPersistHistoryAliasCandidates(
	state providerScanState,
	events []model.Event,
) bool {
	return canPersistHistoryAliasCandidatesWithin(
		state,
		events,
		maxHistoryAliases,
		maxScanStateBytes,
	)
}

func canPersistHistoryAliasCandidatesWithin(
	state providerScanState,
	events []model.Event,
	maxAliases,
	maxBytes int,
) bool {
	if len(events) == 0 {
		return true
	}
	if maxAliases < 0 || maxBytes < 1 ||
		len(state.HistoryAliases)+len(events) > maxAliases {
		return false
	}
	aliases := make(map[string]string, len(state.HistoryAliases)+len(events))
	for eventID, targetID := range state.HistoryAliases {
		aliases[eventID] = targetID
	}
	// Stored event IDs are capped at 128 bytes during state validation. Use a
	// maximum-length target to make this a conservative serialized-size check.
	worstTarget := "codex-h-" + strings.Repeat("x", 128-len("codex-h-"))
	for _, event := range events {
		if isHistoryEventID(event.EventID) {
			aliases[event.EventID] = worstTarget
		}
	}
	state.HistoryAliases = aliases
	encoded, err := json.Marshal(state)
	return err == nil && len(encoded) <= maxBytes
}

func adoptAuthoritativeRecoverySnapshot(
	repoRoot string,
	snapshot map[string]authoritativeFingerprint,
	state *providerScanState,
) error {
	extends, err := authoritativeSetExtends(
		repoRoot,
		state.AuthoritativeFiles,
		snapshot,
	)
	if err != nil {
		return err
	}
	if !extends {
		state.Files = map[string]scanFingerprint{}
		state.Cursors = map[string]scanCursor{}
		state.HistoryAliases = map[string]string{}
	}
	state.AuthoritativeFiles = cloneAuthoritativeFileState(snapshot)
	return nil
}

func updateScanStateStoreSet(repoRoot string, state *providerScanState) error {
	current, err := authoritativeFileState(repoRoot)
	if err != nil {
		return err
	}
	state.AuthoritativeFiles = current
	return nil
}

func revalidateScanStateStoreSet(
	repoRoot string,
	used map[string]authoritativeFingerprint,
	state *providerScanState,
) (bool, error) {
	current, extends, err := authoritativeFileStateExtending(repoRoot, used)
	if err != nil {
		return false, err
	}
	if !extends {
		state.Files = map[string]scanFingerprint{}
		state.Cursors = map[string]scanCursor{}
		state.HistoryAliases = map[string]string{}
	}
	state.AuthoritativeFiles = current
	return extends, nil
}

func scanStateKey(provider, path string) string {
	sum := sha256.Sum256([]byte(provider + "\x00" + filepath.Clean(path)))
	return hex.EncodeToString(sum[:])
}

func validScanFingerprint(fingerprint scanFingerprint) bool {
	if fingerprint.Size < 0 || len(fingerprint.ContentDigest) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(fingerprint.ContentDigest)
	return err == nil
}

func validScannedFileIdentity(identity scannedFileIdentity) bool {
	if !validScanFingerprint(identity.Fingerprint) {
		return false
	}
	if identity.Fingerprint.Size == 0 {
		return identity.PhysicalLines == 0
	}
	return identity.PhysicalLines > 0
}

func sameFingerprintContent(left, right scanFingerprint) bool {
	return left.Size == right.Size && left.ContentDigest == right.ContentDigest
}

func scanCursorIntegrityDigest(key string, cursor scanCursor) string {
	canonical := fmt.Sprintf(
		"%s\x00%d\x00%d\x00%s\x00%d\x00%d",
		key,
		cursor.Fingerprint.Size,
		cursor.Fingerprint.ModifiedUnixNano,
		cursor.Fingerprint.ContentDigest,
		cursor.NextLine,
		cursor.PrefixLines,
	)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func updateScanState(
	state *providerScanState,
	provider,
	path string,
	identity scannedFileIdentity,
) error {
	if !validScannedFileIdentity(identity) {
		return errors.New("refuse to save invalid provider transcript identity")
	}
	if state.Files == nil {
		state.Files = map[string]scanFingerprint{}
	}
	key := scanStateKey(provider, path)
	state.Files[key] = identity.Fingerprint
	delete(state.Cursors, key)
	return nil
}

func stableFileIdentities(
	path string,
	boundaryEnd int64,
) (scannedFileIdentity, scannedFileIdentity, bool, bool, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return scannedFileIdentity{}, scannedFileIdentity{}, false, false, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return scannedFileIdentity{}, scannedFileIdentity{}, false, false, err
	}
	if boundaryEnd < -1 {
		_ = file.Close()
		return scannedFileIdentity{}, scannedFileIdentity{}, false, false,
			errors.New("invalid file digest boundary")
	}
	boundaryAvailable := boundaryEnd >= 0 && boundaryEnd <= opened.Size()
	digestBoundary := boundaryEnd
	if !boundaryAvailable {
		digestBoundary = -1
	}
	full, boundary, digestErr := digestOpenFilePrefix(
		file,
		opened,
		opened.Size(),
		digestBoundary,
	)
	afterHandle, statErr := file.Stat()
	afterPath, pathErr := regularFileInfo(path)
	closeErr := file.Close()
	if digestErr != nil {
		return scannedFileIdentity{}, scannedFileIdentity{}, false, false, digestErr
	}
	if statErr != nil {
		return scannedFileIdentity{}, scannedFileIdentity{}, false, false, statErr
	}
	if pathErr != nil {
		return scannedFileIdentity{}, scannedFileIdentity{}, false, false, pathErr
	}
	if closeErr != nil {
		return scannedFileIdentity{}, scannedFileIdentity{}, false, false, closeErr
	}
	stable := os.SameFile(opened, afterHandle) &&
		os.SameFile(opened, afterPath) &&
		afterHandle.Size() == opened.Size() &&
		afterPath.Size() == opened.Size() &&
		afterHandle.ModTime().UnixNano() == opened.ModTime().UnixNano() &&
		afterPath.ModTime().UnixNano() == opened.ModTime().UnixNano()
	return full, boundary, boundaryAvailable, stable, nil
}

func stableFullFileIdentity(path string) (scannedFileIdentity, bool, error) {
	full, _, _, stable, err := stableFileIdentities(path, -1)
	return full, stable, err
}

// stableFilePrefixIdentities authenticates one historical full snapshot and an
// earlier boundary from the same current handle. Append-only growth beyond end
// is accepted; callers compare both digests before trusting the extension.
func stableFilePrefixIdentities(
	path string,
	end,
	boundaryEnd int64,
) (scannedFileIdentity, scannedFileIdentity, bool, error) {
	if end < 0 || boundaryEnd < 0 || boundaryEnd > end {
		return scannedFileIdentity{}, scannedFileIdentity{}, false,
			errors.New("invalid stable file prefix boundaries")
	}
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return scannedFileIdentity{}, scannedFileIdentity{}, false, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return scannedFileIdentity{}, scannedFileIdentity{}, false, err
	}
	if opened.Size() < end {
		_ = file.Close()
		return scannedFileIdentity{}, scannedFileIdentity{}, false, nil
	}
	full, boundary, digestErr := digestOpenFilePrefix(
		file,
		opened,
		end,
		boundaryEnd,
	)
	afterHandle, statErr := file.Stat()
	afterPath, pathErr := regularFileInfo(path)
	closeErr := file.Close()
	if digestErr != nil {
		return scannedFileIdentity{}, scannedFileIdentity{}, false, digestErr
	}
	if statErr != nil {
		return scannedFileIdentity{}, scannedFileIdentity{}, false, statErr
	}
	if pathErr != nil {
		return scannedFileIdentity{}, scannedFileIdentity{}, false, pathErr
	}
	if closeErr != nil {
		return scannedFileIdentity{}, scannedFileIdentity{}, false, closeErr
	}
	stable := os.SameFile(opened, afterHandle) &&
		os.SameFile(opened, afterPath) &&
		afterHandle.Size() >= end &&
		afterPath.Size() >= end
	return full, boundary, stable, nil
}

func scanStateUnchanged(
	state providerScanState,
	provider,
	path string,
	info os.FileInfo,
) (bool, error) {
	previous, ok := state.Files[scanStateKey(provider, path)]
	if !ok || !validScanFingerprint(previous) || info.Size() != previous.Size {
		return false, nil
	}
	current, stable, err := stableFullFileIdentity(path)
	if err != nil {
		return false, err
	}
	return stable && sameFingerprintContent(previous, current.Fingerprint), nil
}

func scanStartLine(
	state *providerScanState,
	provider,
	path string,
	info os.FileInfo,
) (int, error) {
	if state.Cursors == nil {
		state.Cursors = map[string]scanCursor{}
	}
	key := scanStateKey(provider, path)
	cursor, ok := state.Cursors[key]
	if !ok {
		return 1, nil
	}
	if cursor.NextLine < 2 ||
		cursor.IntegrityDigest != scanCursorIntegrityDigest(key, cursor) ||
		info.Size() < cursor.Fingerprint.Size {
		delete(state.Cursors, key)
		return 1, nil
	}
	prefix, err := filePrefixIdentity(path, cursor.Fingerprint.Size)
	if err != nil {
		return 1, fmt.Errorf("validate provider scan cursor prefix: %w", err)
	}
	if !sameFingerprintContent(prefix.Fingerprint, cursor.Fingerprint) ||
		prefix.PhysicalLines != cursor.PrefixLines ||
		int64(cursor.NextLine) > prefix.PhysicalLines {
		delete(state.Cursors, key)
		return 1, nil
	}
	return cursor.NextLine, nil
}

func updateScanCursor(
	state *providerScanState,
	provider,
	path string,
	identity scannedFileIdentity,
	nextLine int,
) error {
	if nextLine < 2 {
		return nil
	}
	if !validScannedFileIdentity(identity) {
		return errors.New("refuse to save invalid provider scan cursor identity")
	}
	if state.Cursors == nil {
		state.Cursors = map[string]scanCursor{}
	}
	key := scanStateKey(provider, path)
	if int64(nextLine) > identity.PhysicalLines {
		return fmt.Errorf(
			"create provider scan cursor: next line %d exceeds %d physical lines",
			nextLine,
			identity.PhysicalLines,
		)
	}
	delete(state.Files, key)
	cursor := scanCursor{
		Fingerprint: identity.Fingerprint,
		NextLine:    nextLine,
		PrefixLines: identity.PhysicalLines,
	}
	cursor.IntegrityDigest = scanCursorIntegrityDigest(key, cursor)
	state.Cursors[key] = cursor
	return nil
}

func verifyScannedFileIdentity(
	path string,
	snapshot scannedFileIdentity,
	cursor *scanCursor,
) (matches, grew, cursorMatches bool, err error) {
	if !validScannedFileIdentity(snapshot) {
		return false, false, false, errors.New("provider transcript snapshot is invalid")
	}
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return false, false, false, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return false, false, false, err
	}
	if opened.Size() < snapshot.Fingerprint.Size {
		_ = file.Close()
		return false, false, false, nil
	}
	boundaryEnd := int64(-1)
	if cursor != nil && cursor.Fingerprint.Size <= snapshot.Fingerprint.Size {
		boundaryEnd = cursor.Fingerprint.Size
	}
	full, boundary, digestErr := digestOpenFilePrefix(
		file,
		opened,
		snapshot.Fingerprint.Size,
		boundaryEnd,
	)
	afterHandle, statErr := file.Stat()
	afterPath, pathErr := regularFileInfo(path)
	closeErr := file.Close()
	if digestErr != nil {
		return false, false, false, digestErr
	}
	if statErr != nil {
		return false, false, false, statErr
	}
	if pathErr != nil {
		return false, false, false, pathErr
	}
	if closeErr != nil {
		return false, false, false, closeErr
	}
	if !os.SameFile(opened, afterHandle) ||
		!os.SameFile(opened, afterPath) ||
		afterHandle.Size() < snapshot.Fingerprint.Size ||
		afterPath.Size() < snapshot.Fingerprint.Size {
		return false, false, false, nil
	}
	matches = sameFingerprintContent(full.Fingerprint, snapshot.Fingerprint) &&
		full.PhysicalLines == snapshot.PhysicalLines
	grew = afterHandle.Size() > snapshot.Fingerprint.Size ||
		afterPath.Size() > snapshot.Fingerprint.Size
	if cursor == nil {
		return matches, grew, true, nil
	}
	cursorMatches = boundaryEnd >= 0 &&
		sameFingerprintContent(boundary.Fingerprint, cursor.Fingerprint) &&
		boundary.PhysicalLines == cursor.PrefixLines &&
		int64(cursor.NextLine) <= boundary.PhysicalLines
	return matches, grew, cursorMatches, nil
}

func withProviderScanLock(repoRoot, provider string, fn func() error) error {
	if err := validateDirectoryTree(repoRoot, localStoreDir(repoRoot)); err != nil {
		return err
	}
	if err := ensureDirectoryDurableUnder(repoRoot, localStoreDir(repoRoot), 0o700); err != nil {
		return err
	}
	lockPath := filepath.Join(localStoreDir(repoRoot), ".scan-state-"+provider+".lock")
	return withFileLock(lockPath, 2500*time.Millisecond, fn)
}
