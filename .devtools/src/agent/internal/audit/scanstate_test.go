package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

func scanStateFixture(t *testing.T, contents []byte) (string, providerScanState) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(localStoreDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(localStoreDir(root), "local-state.jsonl")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	state := providerScanState{
		Version: currentProviderScanStateVersion,
		Files: map[string]scanFingerprint{
			"cached-transcript": {Size: 123, ModifiedUnixNano: 456},
		},
		AuthoritativeFiles: map[string]authoritativeFingerprint{},
		Cursors:            map[string]scanCursor{},
	}
	if err := updateScanStateStoreSet(root, &state); err != nil {
		t.Fatal(err)
	}
	return root, state
}

func mustFileIdentity(t *testing.T, path string) scannedFileIdentity {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := filePrefixIdentity(path, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestScanStateMigratesLegacyVersionsWithoutQuarantine(t *testing.T) {
	for _, version := range []int{3, 4} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(localStoreDir(root), 0o700); err != nil {
				t.Fatal(err)
			}
			path := scanStatePath(root, "codex")
			stateJSON := fmt.Sprintf(
				`{"version":%d,"authoritative_files":{},"files":{"old":{"size":1,"modified_unix_nano":2}},"cursors":{}}`,
				version,
			)
			if err := os.WriteFile(path, []byte(stateJSON), 0o600); err != nil {
				t.Fatal(err)
			}
			state, err := loadProviderScanState(root, "codex")
			if err != nil {
				t.Fatal(err)
			}
			if state.Version != currentProviderScanStateVersion ||
				state.Cursors == nil ||
				len(state.Files) != 0 {
				t.Fatalf("migrated state = %#v", state)
			}
			matches, err := filepath.Glob(path + ".stale-*")
			if err != nil || len(matches) != 0 {
				t.Fatalf("legacy migration quarantines = %v, %v; want none", matches, err)
			}
		})
	}
}

func TestScanStateCursorResetsWhenTranscriptFingerprintChanges(t *testing.T) {
	state := providerScanState{
		Version:            currentProviderScanStateVersion,
		AuthoritativeFiles: map[string]authoritativeFingerprint{},
		Files:              map[string]scanFingerprint{},
		Cursors:            map[string]scanCursor{},
	}
	path := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateScanCursor(&state, "codex", path, mustFileIdentity(t, path), 2); err != nil {
		t.Fatal(err)
	}
	start, err := scanStartLine(&state, "codex", path, info)
	if err != nil {
		t.Fatal(err)
	}
	if start != 2 {
		t.Fatalf("cursor start = %d, want 2", start)
	}
	if err := os.WriteFile(path, []byte("changed-and-larger\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	start, err = scanStartLine(&state, "codex", path, changed)
	if err != nil {
		t.Fatal(err)
	}
	if start != 1 {
		t.Fatalf("changed fingerprint start = %d, want 1", start)
	}
	if len(state.Cursors) != 0 {
		t.Fatalf("stale cursor survived fingerprint change: %#v", state.Cursors)
	}
}

func TestScanStateCursorRejectsMiddleRewrite(t *testing.T) {
	for _, appendAfterRewrite := range []bool{false, true} {
		name := "same-size-restored-mtime"
		if appendAfterRewrite {
			name = "rewrite-and-append"
		}
		t.Run(name, func(t *testing.T) {
			state := providerScanState{
				Version:            currentProviderScanStateVersion,
				AuthoritativeFiles: map[string]authoritativeFingerprint{},
				Files:              map[string]scanFingerprint{},
				Cursors:            map[string]scanCursor{},
			}
			path := filepath.Join(t.TempDir(), "session.jsonl")
			contents := append([]byte("first\n"), bytes.Repeat([]byte{'a'}, 256*1024)...)
			contents = append(contents, '\n')
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := updateScanCursor(
				&state,
				"codex",
				path,
				mustFileIdentity(t, path),
				2,
			); err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(path, os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteAt([]byte{'Z'}, 128*1024); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if appendAfterRewrite {
				if _, err := file.Seek(0, 2); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if _, err := file.WriteString("later\n"); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if !appendAfterRewrite {
				if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			}
			changed, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			start, err := scanStartLine(&state, "codex", path, changed)
			if err != nil {
				t.Fatal(err)
			}
			if start != 1 {
				t.Fatalf("rewritten prefix start = %d, want 1", start)
			}
			if len(state.Cursors) != 0 {
				t.Fatalf("rewritten prefix retained cursor: %#v", state.Cursors)
			}
		})
	}
}

func TestScanStateCursorRejectsNextLineBeyondEOF(t *testing.T) {
	state := providerScanState{
		Version:            currentProviderScanStateVersion,
		AuthoritativeFiles: map[string]authoritativeFingerprint{},
		Files:              map[string]scanFingerprint{},
		Cursors:            map[string]scanCursor{},
	}
	path := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	identity := mustFileIdentity(t, path)
	key := scanStateKey("codex", path)
	cursor := scanCursor{
		Fingerprint: identity.Fingerprint,
		NextLine:    3,
		PrefixLines: identity.PhysicalLines,
	}
	cursor.IntegrityDigest = scanCursorIntegrityDigest(key, cursor)
	state.Cursors[key] = cursor
	start, err := scanStartLine(&state, "codex", path, info)
	if err != nil {
		t.Fatal(err)
	}
	if start != 1 {
		t.Fatalf("impossible cursor start = %d, want 1", start)
	}
	if len(state.Cursors) != 0 {
		t.Fatalf("impossible cursor survived: %#v", state.Cursors)
	}
}

func TestScanStateCursorSurvivesVerifiedAppendOnlyGrowth(t *testing.T) {
	state := providerScanState{
		Version:            currentProviderScanStateVersion,
		AuthoritativeFiles: map[string]authoritativeFingerprint{},
		Files:              map[string]scanFingerprint{},
		Cursors:            map[string]scanCursor{},
	}
	path := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(path, []byte("first\nsecond\nthird\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateScanCursor(&state, "codex", path, mustFileIdentity(t, path), 3); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("fourth\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	grown, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	start, err := scanStartLine(&state, "codex", path, grown)
	if err != nil {
		t.Fatal(err)
	}
	if start != 3 {
		t.Fatalf("append-only cursor start = %d, want 3", start)
	}
}

func TestProviderFileSnapshotUsesFixedInitialSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	initial := []byte("first\nsecond\n")
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	reader, tracker, info, err := beginProviderFileSnapshot(file)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	appender, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := appender.WriteString("third\n"); err != nil {
		_ = appender.Close()
		_ = file.Close()
		t.Fatal(err)
	}
	if err := appender.Close(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	snapshot, err := finishProviderFileSnapshot(tracker, info)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Fingerprint.Size != int64(len(initial)) {
		t.Fatalf("snapshot size = %d, want %d", snapshot.Fingerprint.Size, len(initial))
	}
	sum := sha256.Sum256(initial)
	if snapshot.Fingerprint.ContentDigest != hex.EncodeToString(sum[:]) {
		t.Fatalf("snapshot digest = %s, want initial prefix", snapshot.Fingerprint.ContentDigest)
	}
}

func TestVerifyScannedFileIdentityBindsCursorToScannedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	first := []byte("metaA\npromptA\nend\n")
	second := []byte("metaB\npromptB\nend\n")
	if len(first) != len(second) {
		t.Fatal("test fixtures must have equal size")
	}
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	firstIdentity := mustFileIdentity(t, path)
	cursor := scanCursor{
		Fingerprint: firstIdentity.Fingerprint,
		NextLine:    2,
		PrefixLines: firstIdentity.PhysicalLines,
	}
	if err := os.WriteFile(path, second, 0o600); err != nil {
		t.Fatal(err)
	}
	secondIdentity := mustFileIdentity(t, path)
	matches, grew, cursorMatches, err := verifyScannedFileIdentity(
		path,
		secondIdentity,
		&cursor,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !matches || grew || cursorMatches {
		t.Fatalf(
			"verification = matches:%v grew:%v cursor:%v; want true,false,false",
			matches,
			grew,
			cursorMatches,
		)
	}
	matches, _, _, err = verifyScannedFileIdentity(path, firstIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	if matches {
		t.Fatal("replacement content matched the prior scanner snapshot")
	}
}

func TestVerifyScannedFileIdentityAcceptsOnlyAppendAfterSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := mustFileIdentity(t, path)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("third\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	matches, grew, cursorMatches, err := verifyScannedFileIdentity(path, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !matches || !grew || !cursorMatches {
		t.Fatalf(
			"append verification = matches:%v grew:%v cursor:%v; want true,true,true",
			matches,
			grew,
			cursorMatches,
		)
	}
}

func TestCompletedScanStateDetectsSameSizeRewriteWithRestoredMtime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	first := []byte("first-A\nsecond-A\n")
	second := []byte("first-B\nsecond-B\n")
	if len(first) != len(second) {
		t.Fatal("test fixtures must have equal size")
	}
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	state := providerScanState{
		Version:            currentProviderScanStateVersion,
		AuthoritativeFiles: map[string]authoritativeFingerprint{},
		Files:              map[string]scanFingerprint{},
		Cursors:            map[string]scanCursor{},
	}
	if err := updateScanState(&state, "codex", path, mustFileIdentity(t, path)); err != nil {
		t.Fatal(err)
	}
	unchanged, err := scanStateUnchanged(state, "codex", path, info)
	if err != nil || !unchanged {
		t.Fatalf("initial unchanged = %v, %v; want true, nil", unchanged, err)
	}
	if err := os.WriteFile(path, second, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	rewritten, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err = scanStateUnchanged(state, "codex", path, rewritten)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged {
		t.Fatal("completed state skipped same-size rewritten content")
	}
}

func TestScanStateKeepsTranscriptFingerprintsAfterAppendOnlyGrowth(t *testing.T) {
	root, state := scanStateFixture(t, []byte("stable-first-record\nold-tail\n"))
	path := filepath.Join(localStoreDir(root), "local-state.jsonl")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("new-append-only-record\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := invalidateScanStateIfStoreSetChanged(root, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Files) != 1 {
		t.Fatalf("append-only growth invalidated transcript fingerprints: %#v", state.Files)
	}
}

func TestScanStateInvalidatesLargerSameNameReplacement(t *testing.T) {
	root, state := scanStateFixture(t, []byte("stable-first-record\nold-tail\n"))
	path := filepath.Join(localStoreDir(root), "local-state.jsonl")
	replacement := []byte("stable-first-record\nreplacement-content-that-is-larger-than-the-old-tail\n")
	if err := os.WriteFile(path, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := invalidateScanStateIfStoreSetChanged(root, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Files) != 0 {
		t.Fatalf("larger same-name replacement retained stale fingerprints: %#v", state.Files)
	}
}

func TestScanStateInvalidatesSameSizeReplacementEvenWithRestoredMtime(t *testing.T) {
	root, state := scanStateFixture(t, []byte("stable-first-record\nAAAA\n"))
	path := filepath.Join(localStoreDir(root), "local-state.jsonl")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("stable-first-record\nBBBB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	// Some filesystems round mtimes. Ensure the test remains about content by
	// allowing the implementation to see an exactly restored timestamp.
	restored, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ModTime().Sub(info.ModTime()) > time.Millisecond {
		t.Skip("filesystem cannot restore mtime precisely enough for this test")
	}
	if err := invalidateScanStateIfStoreSetChanged(root, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Files) != 0 {
		t.Fatalf("same-size replacement retained stale fingerprints: %#v", state.Files)
	}
}

func TestScanStateRejectsSymlinkFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(localStoreDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-state.json")
	if err := os.WriteFile(
		outside,
		[]byte(`{"version":3,"authoritative_files":{},"files":{}}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	requireFileSymlink(t, outside, scanStatePath(root, "codex"))
	if _, err := loadProviderScanState(root, "codex"); err == nil {
		t.Fatal("loadProviderScanState accepted a symbolic-link state file")
	}

	authoritativeLink := filepath.Join(localStoreDir(root), "local-symlink.jsonl")
	requireFileSymlink(t, outside, authoritativeLink)
	if _, err := authoritativeFileState(root); err == nil {
		t.Fatal("authoritativeFileState accepted a symbolic-link backup")
	}
}

func TestHistoryAliasSizeGuardUsesMaximumTargetLength(t *testing.T) {
	state := emptyProviderScanState()
	state.HistoryAliases["codex-h-existing"] =
		"codex-h-" + strings.Repeat("x", 128-len("codex-h-"))
	candidate := sampleEvent("codex-h-candidate", "prompt")
	if canPersistHistoryAliasCandidatesWithin(
		state,
		[]model.Event{candidate},
		10,
		256,
	) {
		t.Fatal("history alias guard accepted a state beyond its byte budget")
	}
	if !canPersistHistoryAliasCandidatesWithin(
		state,
		[]model.Event{candidate},
		10,
		4096,
	) {
		t.Fatal("history alias guard rejected an in-budget state")
	}
}
