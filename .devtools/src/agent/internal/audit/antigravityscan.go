package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
	"github.com/acme/prompt-audit-template/internal/sqliteread"
)

// Antigravity is the one supported provider with no hook of any kind, so this
// scanner is its only capture path — there is no direct capture to fall back on
// and nothing to correlate against. Everything it imports, it imports here.
//
// Its conversations live in per-conversation SQLite stores under
// ~/.gemini/antigravity/conversations. The prompt text sits inside a protobuf
// blob, at an exact field path; the workspace folder that owns the conversation
// sits in a separate metadata blob. Both were established by reading real
// stores, not from any published schema — see the format notes below.
const (
	antigravityHomeEnv = "ANTIGRAVITY_HOME"
	geminiHomeEnv      = "GEMINI_HOME"

	// stepTypeUserMessage is the step kind that carries what the worker typed.
	// Verified across real conversations: the assistant's own turns are a
	// different kind and never appear under it.
	stepTypeUserMessage = 14

	// Column positions in the steps table, by the order the schema declares
	// them: idx, step_type, status, has_subtrajectory, metadata, error_details,
	// permissions, task_details, render_info, step_payload, step_format.
	antigravityStepTypeColumn = 1
	antigravityPayloadColumn  = 9
	antigravityMinColumns     = 10

	// maxAntigravityStoreBytes keeps one pathological store from dominating a
	// bounded recovery pass. Real conversation stores are single-digit MiB.
	maxAntigravityStoreBytes = 256 << 20
)

// antigravityPromptField is the protobuf path to the prompt inside a user step.
//
// It is matched EXACTLY, never by "the longest string in the payload". That
// heuristic was tried and it silently picked the wrong field in four of five
// real prompts, returning an internal allow-list of shell commands
// (command(adb), command(gradlew)...) instead of what the worker wrote. Machine
// text reaching the register is the failure this project cannot have, so the
// path is exact and a payload without it is skipped rather than guessed at.
var antigravityPromptField = []int{19, 2}

// antigravityWorkspaceFields are the paths where a conversation records the
// folder it belongs to. Several are checked because the same URI appears in
// more than one place and any of them is enough to scope the conversation.
var antigravityWorkspaceFields = [][]int{{1, 1}, {1, 2}, {7}}

func antigravityConversationsRoot() string {
	if home := strings.TrimSpace(os.Getenv(antigravityHomeEnv)); home != "" {
		return filepath.Join(home, "conversations")
	}
	if home := strings.TrimSpace(os.Getenv(geminiHomeEnv)); home != "" {
		return filepath.Join(home, "antigravity", "conversations")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".gemini", "antigravity", "conversations")
}

// antigravityHistoryEventID identifies a prompt across passes.
//
// It deliberately excludes the prompt text and the timestamp. The text is
// redacted before storage, so keying on it would re-import the whole history
// the first time a redaction rule changed; the timestamp is read from an
// inferred field with no published schema. The conversation id and the step
// index are stable for the life of the store, which is what an identity needs.
func antigravityHistoryEventID(conversationID string, index int64) string {
	sum := sha256.Sum256([]byte(
		"antigravity-history-v1\x00" + conversationID + "\x00" + fmt.Sprint(index),
	))
	return "antigravity-h-" + hex.EncodeToString(sum[:16])
}

// protoField follows an exact protobuf field path and returns the first match.
// It parses wire format only: no schema is available, and none is assumed
// beyond the path itself.
func protoField(buf []byte, path ...int) ([]byte, bool) {
	if len(path) == 0 {
		return buf, true
	}
	want := path[0]
	index := 0
	for index < len(buf) {
		key, next, ok := protoVarint(buf, index)
		if !ok {
			return nil, false
		}
		index = next
		number, wire := int(key>>3), key&7
		switch wire {
		case 0:
			if _, index, ok = protoVarint(buf, index); !ok {
				return nil, false
			}
		case 1:
			index += 8
		case 5:
			index += 4
		case 2:
			length, after, ok := protoVarint(buf, index)
			if !ok || length > uint64(len(buf)) {
				return nil, false
			}
			index = after
			if index+int(length) > len(buf) {
				return nil, false
			}
			chunk := buf[index : index+int(length)]
			index += int(length)
			if number == want {
				if len(path) == 1 {
					return chunk, true
				}
				if inner, ok := protoField(chunk, path[1:]...); ok {
					return inner, true
				}
			}
		default:
			return nil, false
		}
		if index < 0 || index > len(buf) {
			return nil, false
		}
	}
	return nil, false
}

func protoVarint(buf []byte, index int) (uint64, int, bool) {
	var result uint64
	var shift uint
	for {
		if index >= len(buf) || shift > 63 {
			return 0, index, false
		}
		current := buf[index]
		index++
		result |= uint64(current&0x7f) << shift
		if current&0x80 == 0 {
			return result, index, true
		}
		shift += 7
	}
}

// antigravityStoreBelongsToRepository decides scope BEFORE any prompt payload is
// read. A worker's other projects are in the same directory, so opening their
// conversations at all is what must be avoided — not merely declining to store
// them afterwards.
func antigravityStoreBelongsToRepository(db *sqliteread.DB, repoRoot string) (bool, error) {
	decided := false
	inside := false
	var scanErr error
	err := db.ScanTable("trajectory_metadata_blob", func(_ int64, columns []sqliteread.Value) bool {
		for _, column := range columns {
			if column.Kind != sqliteread.KindBlob {
				continue
			}
			for _, path := range antigravityWorkspaceFields {
				raw, ok := protoField(column.Bytes, path...)
				if !ok {
					continue
				}
				folder, ok := antigravityFolderPath(string(raw))
				if !ok {
					continue
				}
				switch classifyProviderCWD(folder, repoRoot) {
				case providerPathInside:
					decided, inside = true, true
					return false
				case providerPathOutside:
					decided, inside = true, false
					return false
				}
			}
		}
		return true
	})
	if err != nil {
		return false, err
	}
	if scanErr != nil {
		return false, scanErr
	}
	if !decided {
		// An unscoped conversation is never imported: without a folder there is
		// no evidence it belongs to this repository, and guessing would leak
		// another project's prompts.
		return false, nil
	}
	return inside, nil
}

// antigravityFolderPath turns a recorded workspace URI into a local path.
func antigravityFolderPath(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", false
	}
	index := strings.Index(value, "file://")
	if index < 0 {
		return "", false
	}
	value = value[index:]
	if end := strings.IndexAny(value, "\x00\n\r\""); end >= 0 {
		value = value[:end]
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "file" {
		return "", false
	}
	path := parsed.Path
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return "", false
	}
	return filepath.FromSlash(path), true
}

// scanAntigravityStore reads one conversation store. Scope is settled first, so
// a store belonging to another project is closed without its prompts ever being
// decoded.
func scanAntigravityStore(
	path string,
	repoRoot string,
	storeFallback time.Time,
	collector *recoveredPromptCollector,
	skipKnown func(scannedPrompt) bool,
	observeCandidate func(scannedPrompt),
) (bool, error) {
	db, err := sqliteread.Open(path)
	if err != nil {
		return false, err
	}
	defer db.Close()

	belongs, err := antigravityStoreBelongsToRepository(db, repoRoot)
	if err != nil || !belongs {
		return false, err
	}

	conversationID := strings.TrimSuffix(filepath.Base(path), ".db")
	collected := make([]scannedPrompt, 0, 8)
	full := false
	scanErr := db.ScanTable("steps", func(rowid int64, columns []sqliteread.Value) bool {
		if len(columns) < antigravityMinColumns {
			return true
		}
		kind := columns[antigravityStepTypeColumn]
		if kind.Kind != sqliteread.KindInt || kind.Int != stepTypeUserMessage {
			return true
		}
		payload := columns[antigravityPayloadColumn]
		if payload.Kind != sqliteread.KindBlob {
			return true
		}
		raw, ok := protoField(payload.Bytes, antigravityPromptField...)
		if !ok {
			// No prompt field: a step shape this build does not understand.
			// Skipping one step is always safer than guessing at its contents.
			return true
		}
		text := string(raw)
		if strings.TrimSpace(text) == "" {
			return true
		}
		prompt := scannedPrompt{
			SessionID: conversationID,
			Position:  int(rowid),
			Prompt:    text,
			Timestamp: antigravityStepTime(payload.Bytes, storeFallback),
		}
		if observeCandidate != nil {
			observeCandidate(prompt)
		}
		if skipKnown != nil && skipKnown(prompt) {
			return true
		}
		collected = append(collected, prompt)
		return true
	})
	if scanErr != nil {
		return false, scanErr
	}
	if !collector.AddAll(collected) {
		full = true
	}
	return full, nil
}

// antigravityStepTimeMessage is the message holding when a step happened, and
// antigravityStepTimeSeconds is the field inside it carrying seconds since the
// epoch. Located by walking real user steps and checking which varints land in
// a plausible epoch range; the values matched the wall-clock minutes at which
// the prompts were actually typed.
var (
	antigravityStepTimeMessage = []int{5, 1}
	antigravityStepTimeSeconds = 1
)

// protoVarintField reads a varint field out of a message. protoField can only
// return length-delimited fields, and a timestamp is a plain varint inside its
// enclosing message, so navigating to the message and reading the number needs
// this second step.
func protoVarintField(buf []byte, number int) (uint64, bool) {
	index := 0
	for index < len(buf) {
		key, next, ok := protoVarint(buf, index)
		if !ok {
			return 0, false
		}
		index = next
		field, wire := int(key>>3), key&7
		switch wire {
		case 0:
			value, after, ok := protoVarint(buf, index)
			if !ok {
				return 0, false
			}
			index = after
			if field == number {
				return value, true
			}
		case 1:
			index += 8
		case 5:
			index += 4
		case 2:
			length, after, ok := protoVarint(buf, index)
			if !ok || after+int(length) > len(buf) {
				return 0, false
			}
			index = after + int(length)
		default:
			return 0, false
		}
	}
	return 0, false
}

// antigravityStepTime reports when a step happened. The enclosing message sits
// at antigravityStepTimeMessage and carries the seconds as its first field.
//
// A prompt with no usable time cannot be stored — the event contract requires
// one — so the store's own last write is used as the floor rather than dropping
// the prompt. That is late rather than wrong, and losing a prompt is the worse
// failure of the two.
func antigravityStepTime(payload []byte, fallback time.Time) time.Time {
	message, ok := protoField(payload, antigravityStepTimeMessage...)
	if !ok {
		return fallback
	}
	seconds, ok := protoVarintField(message, antigravityStepTimeSeconds)
	if !ok || !plausibleEpochSeconds(seconds) {
		return fallback
	}
	return time.Unix(int64(seconds), 0).UTC()
}

// plausibleEpochSeconds rejects values that cannot be a capture time, so an
// unrelated counter is never mistaken for a date.
func plausibleEpochSeconds(value uint64) bool {
	const year2020 = 1_577_836_800
	const year2100 = 4_102_444_800
	return value > year2020 && value < year2100
}

func scanAntigravityPrompts(
	repoRoot string,
	state *providerScanState,
	newCollector func() *recoveredPromptCollector,
	skipKnown func(scannedPrompt) bool,
	observeCandidate func(scannedPrompt),
) ([]scannedPrompt, bool, error) {
	root := antigravityConversationsRoot()
	if root == "" {
		return nil, false, nil
	}
	if _, err := os.Stat(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("inspect Antigravity conversations directory: %w", err)
	}
	anchor := cloneAnchorTime(repoRoot)
	all := newCollector()
	var problems problemCollector
	pendingBatch := false

	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkError error) error {
		if walkError != nil {
			problems.Add(fmt.Errorf("walk Antigravity conversations: %w", walkError))
			return nil
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".db") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			problems.Add(fmt.Errorf("stat Antigravity conversation: %w", err))
			return nil
		}
		if info.Size() > maxAntigravityStoreBytes {
			problems.Add(errors.New("Antigravity conversation exceeds the bounded scan size"))
			return nil
		}
		// A store whose last write predates the clone cannot hold a prompt that
		// belongs to it. The write-ahead log carries the recent writes, so its
		// time is what decides.
		newest := newestAntigravityWrite(path, info)
		if transcriptPredatesClone(newest, anchor) {
			return nil
		}
		// No incremental per-file state is kept for these stores, on purpose.
		// The scan-state machinery fingerprints append-only transcripts and
		// resumes them by line cursor; a SQLite store mutates in place and
		// keeps its recent writes in a separate log, so a fingerprint that
		// looked unchanged could hide a conversation that had gained prompts.
		// Re-reading an in-scope store every pass is cheap — only this
		// repository's conversations are ever opened past their metadata — and
		// re-importing is impossible anyway because the event id is stable.
		full, storeErr := scanAntigravityStore(
			path, repoRoot, newest.ModTime().UTC(), all, skipKnown, observeCandidate,
		)
		if storeErr != nil {
			problems.Add(fmt.Errorf("scan Antigravity conversation: %w", storeErr))
			return nil
		}
		if full {
			pendingBatch = true
		}
		return nil
	})
	if walkErr != nil {
		problems.Add(walkErr)
	}
	if err := all.Err("Antigravity conversations"); err != nil {
		problems.Add(err)
	}
	return all.Values(), pendingBatch, problems.Err("Antigravity conversations")
}

// newestAntigravityWrite reports the most recent write across the store and its
// write-ahead log. The main file can sit untouched for a long time while every
// recent prompt lands in the log beside it, so its own timestamp is not enough.
func newestAntigravityWrite(path string, info fs.FileInfo) fs.FileInfo {
	newest := info
	for _, companion := range []string{path + "-wal", path + "-shm"} {
		other, err := os.Stat(companion)
		if err != nil {
			continue
		}
		if other.ModTime().After(newest.ModTime()) {
			newest = other
		}
	}
	return newest
}

func scanAndStoreAntigravityPrompts(repo RepositoryInfo) (int, error) {
	if !repo.Project.LocalStore || !repo.Project.toolEnabled(model.ToolAntigravity) {
		return 0, nil
	}
	added := 0
	err := withProviderScanLock(repo.Root, model.ToolAntigravity, func() error {
		state, err := loadProviderScanState(repo.Root, model.ToolAntigravity)
		if err != nil {
			return err
		}
		if err := invalidateScanStateIfStoreSetChanged(repo.Root, &state); err != nil {
			return err
		}
		redactor, redactErr := NewRedactor(
			repo.Project.RedactSecrets,
			repo.Project.RedactionPatterns,
		)
		if redactErr != nil {
			return redactErr
		}
		existing, dedupeStoreSet, existingErr := readAuthoritativeRecoverySnapshot(repo.Root)
		if existingErr != nil {
			return existingErr
		}
		if adoptErr := adoptAuthoritativeRecoverySnapshot(repo.Root, dedupeStoreSet, &state); adoptErr != nil {
			return adoptErr
		}
		anchor := cloneAnchorTime(repo.Root)
		buildHistoryEvent := func(prompt scannedPrompt) model.Event {
			return model.Event{
				EventID:   antigravityHistoryEventID(prompt.SessionID, int64(prompt.Position)),
				Timestamp: prompt.Timestamp,
				Tool:      model.ToolAntigravity,
				SessionID: prompt.SessionID,
				Prompt:    boundRedactedPrompt(redactor.Redact(prompt.Prompt)),
			}
		}
		deduper := newRecoveredPromptDeduper(
			existing,
			buildHistoryEvent,
			func() {
				recordLocalHealth(
					repo.Root,
					"history transform drift detected; authoritative event retained",
				)
			},
		)
		deduper.AddHistoryAliases(state.HistoryAliases)
		skipKnown := func(prompt scannedPrompt) bool {
			if !anchor.IsZero() && !prompt.Timestamp.IsZero() && prompt.Timestamp.Before(anchor) {
				return true
			}
			return deduper.Skip(prompt)
		}
		prompts, pendingBatch, scanErr := scanAntigravityPrompts(
			repo.Root,
			&state,
			newRecoveredPromptCollector,
			skipKnown,
			deduper.ObserveExact,
		)
		_, email, _ := automaticIdentity(repo.Root)
		userID := localUserID(email)
		events := make([]model.Event, 0, len(prompts))
		for _, prompt := range prompts {
			if !anchor.IsZero() && !prompt.Timestamp.IsZero() && prompt.Timestamp.Before(anchor) {
				continue
			}
			event := buildHistoryEvent(prompt)
			event.UserID = userID
			event.UserEmail = email
			event.RepositoryName = repo.Name
			event.RepositoryRemote = repositoryRemoteForEvent(repo)
			event.Branch = repo.Branch
			event.CommitHash = repo.CommitHash
			events = append(events, event)
		}
		reservedHistoryIDs := make(map[string]bool)
		reserveAllExistingHistoryIDs(existing, model.ToolAntigravity, reservedHistoryIDs)
		var storeErr error
		added, _, storeErr = appendNewLocalEventsDetailed(
			repo.Root,
			userID,
			events,
			reservedHistoryIDs,
		)
		if storeErr != nil {
			return errors.Join(scanErr, storeErr)
		}
		storeSetSafe, stateErr := revalidateScanStateStoreSet(repo.Root, dedupeStoreSet, &state)
		if stateErr != nil {
			return errors.Join(scanErr, stateErr)
		}
		if !storeSetSafe {
			pendingBatch = true
		}
		stateErr = saveProviderScanState(repo.Root, model.ToolAntigravity, state)
		var pendingErr error
		if pendingBatch {
			pendingErr = errProviderRecoveryPending
		}
		return errors.Join(scanErr, stateErr, pendingErr)
	})
	return added, err
}
