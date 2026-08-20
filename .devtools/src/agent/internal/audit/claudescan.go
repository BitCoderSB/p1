package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

// Claude Code writes sessions to ~/.claude/projects/<slug>/<session>.jsonl.
// This scanner is a recovery path for gaps in the direct UserPromptSubmit hook;
// it remains project-scoped and never treats transcript scanning as proof that
// the project hook was trusted or active.
//
// Only genuine typed prompts are eligible for storage. A record qualifies when it is
// type="user", not a sidechain (sub-agent side conversation), carries
// origin.kind="human", and its message content is text the user typed rather
// than a tool_result being fed back. Assistant output, tool results and
// slash-command noise (origin.kind absent) are all skipped, so no AI response
// or injected context ever reaches the registry.

type claudeRecord struct {
	Type        string          `json:"type"`
	Timestamp   string          `json:"timestamp"`
	IsSidechain bool            `json:"isSidechain"`
	CWD         string          `json:"cwd"`
	Origin      json.RawMessage `json:"origin"`
	Message     json.RawMessage `json:"message"`
}

type claudeMessage struct {
	Content json.RawMessage `json:"content"`
}

func claudeProjectsRoot() string {
	if dir := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); dir != "" {
		return filepath.Join(dir, "projects")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", "projects")
}

// claudeHistoryEventID combines session, physical line and provider timestamp,
// so repaired or inserted rows cannot steal an existing prompt ID.
func claudeHistoryEventID(sessionID string, position int, timestamp time.Time) string {
	sum := sha256.Sum256([]byte(
		"claude-history-v2\x00" + sessionID + "\x00" + strconv.Itoa(position) +
			"\x00" + timestamp.UTC().Format(time.RFC3339Nano),
	))
	return "claude-h-" + hex.EncodeToString(sum[:16])
}

// claudeOriginIsHuman reports whether origin.kind == "human". Genuine typed
// prompts carry this; slash-command output, caveats and injected context do not.
func claudeOriginIsHuman(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var origin struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(raw, &origin) != nil {
		return false
	}
	return origin.Kind == "human"
}

// claudeHumanText returns the user's typed text for a message whose content is
// either a plain string or an array of content blocks. Any tool_result block
// disqualifies the record: that is tool output being fed back to the model, not
// something the user typed.
func claudeHumanText(content json.RawMessage) (string, bool) {
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" || trimmed == "null" {
		return "", false
	}
	// The common typed-prompt shape is a plain JSON string.
	var s string
	if json.Unmarshal(content, &s) == nil {
		return s, true
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &blocks) != nil {
		return "", false
	}
	var builder strings.Builder
	for _, block := range blocks {
		if block.Type == "tool_result" {
			return "", false
		}
		if block.Type == "text" {
			if builder.Len() > 0 {
				builder.WriteString("\n")
			}
			builder.WriteString(block.Text)
		}
	}
	return builder.String(), true
}

func scanClaudeFile(path, repoRoot string) ([]scannedPrompt, error) {
	prompts, nextLine, err := scanClaudeFilePage(
		path,
		repoRoot,
		1,
		newRecoveredPromptCollector(),
	)
	if nextLine != 0 {
		err = errors.Join(err, errProviderRecoveryPending)
	}
	return prompts, err
}

func scanClaudeFilePage(
	path,
	repoRoot string,
	startLine int,
	prompts *recoveredPromptCollector,
) ([]scannedPrompt, int, error) {
	found, nextLine, _, err := scanClaudeFilePageSnapshot(
		path,
		repoRoot,
		startLine,
		prompts,
		nil,
		nil,
	)
	return found, nextLine, err
}

func scanClaudeFilePageSnapshot(
	path,
	repoRoot string,
	startLine int,
	prompts *recoveredPromptCollector,
	skipKnown func(scannedPrompt) bool,
	observeCandidate func(scannedPrompt),
) ([]scannedPrompt, int, scannedFileIdentity, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, 0, scannedFileIdentity{}, fmt.Errorf("open Claude session: %w", err)
	}
	defer file.Close()
	snapshotReader, tracker, snapshotInfo, err := beginProviderFileSnapshot(file)
	if err != nil {
		return nil, 0, scannedFileIdentity{}, fmt.Errorf("snapshot Claude session: %w", err)
	}
	if startLine < 1 {
		startLine = 1
	}

	// The file name is the Claude session id (e.g. <uuid>.jsonl).
	sessionID := strings.TrimSuffix(filepath.Base(path), ".jsonl")

	reader := bufio.NewReaderSize(
		snapshotReader,
		providerLineBufferSize(maxProviderTranscriptLineBytes),
	)
	var problems problemCollector
	lineNumber := 0
	nextLine := 0
	for {
		line, eof, readErr := readBoundedProviderLine(reader, maxProviderTranscriptLineBytes)
		if eof {
			break
		}
		lineNumber++
		if errors.Is(readErr, errProviderLineTooLong) {
			problems.Add(fmt.Errorf("Claude session line %d exceeds the size limit", lineNumber))
			continue
		}
		if readErr != nil {
			problems.Add(fmt.Errorf("read Claude session: %w", readErr))
			break
		}
		if len(line) == 0 {
			continue
		}
		var record claudeRecord
		if !isJSONObject(line) ||
			validateUniqueJSONKeys(line) != nil ||
			json.Unmarshal(line, &record) != nil ||
			strings.TrimSpace(record.Type) == "" {
			problems.Add(fmt.Errorf("Claude session contains invalid JSON on line %d", lineNumber))
			continue
		}
		if record.Type != "user" || record.IsSidechain {
			continue
		}
		if !claudeOriginIsHuman(record.Origin) {
			continue
		}
		// Scope before validating user content so a malformed turn from a cwd
		// outside this repository cannot degrade this project's health.
		cwdScope := classifyProviderCWD(record.CWD, repoRoot)
		if cwdScope == providerPathIndeterminate {
			problems.Add(fmt.Errorf("Claude user event cwd cannot be verified on line %d", lineNumber))
			continue
		}
		if cwdScope != providerPathInside {
			continue
		}
		var message claudeMessage
		if !isJSONObject(record.Message) || json.Unmarshal(record.Message, &message) != nil {
			problems.Add(fmt.Errorf("Claude user message is invalid on line %d", lineNumber))
			continue
		}
		content := strings.TrimSpace(string(message.Content))
		if content == "" || content == "null" || (content[0] != '"' && content[0] != '[') {
			problems.Add(fmt.Errorf("Claude user message content is invalid on line %d", lineNumber))
			continue
		}
		text, ok := claudeHumanText(message.Content)
		if !ok || strings.TrimSpace(text) == "" {
			continue
		}
		timestamp := parseCodexTimestamp(record.Timestamp)
		if timestamp.IsZero() {
			problems.Add(fmt.Errorf("Claude user event has no valid timestamp on line %d", lineNumber))
			continue
		}
		candidate := scannedPrompt{
			SessionID: sessionID,
			Position:  lineNumber,
			Prompt:    text,
			Timestamp: timestamp,
		}
		if observeCandidate != nil {
			observeCandidate(candidate)
		}
		if lineNumber < startLine {
			if skipKnown != nil {
				skipKnown(candidate)
			}
			continue
		}
		if nextLine != 0 {
			continue
		}
		if skipKnown != nil && skipKnown(candidate) {
			continue
		}
		if prompts.TryAdd(candidate) == recoveredPromptBatchFull {
			nextLine = lineNumber
		}
	}
	identity, identityErr := finishProviderFileSnapshot(tracker, snapshotInfo)
	return prompts.Values(), nextLine, identity, errors.Join(
		problems.Err("Claude session"),
		prompts.Err("Claude session"),
		identityErr,
	)
}

func scanClaudePrompts(
	repoRoot string,
	state *providerScanState,
) ([]scannedPrompt, bool, error) {
	return scanClaudePromptsFiltered(repoRoot, state, nil, nil)
}

func scanClaudePromptsFiltered(
	repoRoot string,
	state *providerScanState,
	skipKnown func(scannedPrompt) bool,
	observeCandidate func(scannedPrompt),
) ([]scannedPrompt, bool, error) {
	root := claudeProjectsRoot()
	if root == "" {
		return nil, false, nil
	}
	if _, err := os.Stat(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("inspect Claude sessions directory: %w", err)
	}
	// See transcriptPredatesClone: a transcript last written before this clone
	// existed cannot hold a prompt that belongs to it, so it is skipped from the
	// directory entry without ever being opened.
	anchor := cloneAnchorTime(repoRoot)
	all := newRecoveredPromptCollector()
	var problems problemCollector
	pendingBatch := false
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkError error) error {
		if walkError != nil {
			problems.Add(fmt.Errorf("walk Claude sessions: %w", walkError))
			return nil
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			problems.Add(fmt.Errorf("stat Claude session: %w", err))
			return nil
		}
		if transcriptPredatesClone(info, anchor) {
			return nil
		}
		unchanged, unchangedErr := scanStateUnchanged(
			*state,
			model.ToolClaudeCode,
			path,
			info,
		)
		if unchangedErr != nil {
			problems.Add(fmt.Errorf("authenticate Claude session state: %w", unchangedErr))
			return nil
		}
		if unchanged {
			return nil
		}
		startLine, cursorErr := scanStartLine(state, model.ToolClaudeCode, path, info)
		if cursorErr != nil {
			problems.Add(cursorErr)
			return nil
		}
		var resumedCursor *scanCursor
		if startLine > 1 {
			cursor := state.Cursors[scanStateKey(model.ToolClaudeCode, path)]
			resumedCursor = &cursor
		}
		prompts, nextLine, snapshot, scanErr := scanClaudeFilePageSnapshot(
			path,
			repoRoot,
			startLine,
			newRecoveredPromptCollector(),
			skipKnown,
			observeCandidate,
		)
		matches, grew, cursorMatches, verifyErr := verifyScannedFileIdentity(
			path,
			snapshot,
			resumedCursor,
		)
		if verifyErr != nil || !matches {
			delete(state.Cursors, scanStateKey(model.ToolClaudeCode, path))
			pendingBatch = true
			if verifyErr != nil {
				problems.Add(fmt.Errorf("verify Claude session snapshot: %w", verifyErr))
			}
			return nil
		}
		if resumedCursor != nil && !cursorMatches {
			delete(state.Cursors, scanStateKey(model.ToolClaudeCode, path))
			pendingBatch = true
			return nil
		}
		buffered := all.AddAll(prompts)
		if scanErr != nil {
			problems.Add(scanErr)
			return nil
		}
		if !buffered {
			pendingBatch = true
			return nil
		}
		if nextLine != 0 {
			if cursorErr := updateScanCursor(
				state,
				model.ToolClaudeCode,
				path,
				snapshot,
				nextLine,
			); cursorErr != nil {
				problems.Add(cursorErr)
				return nil
			}
			pendingBatch = true
		} else {
			if stateErr := updateScanState(
				state,
				model.ToolClaudeCode,
				path,
				snapshot,
			); stateErr != nil {
				problems.Add(stateErr)
				return nil
			}
			if grew {
				pendingBatch = true
			}
		}
		return nil
	})
	if walkErr != nil {
		problems.Add(walkErr)
	}
	return all.Values(), pendingBatch, errors.Join(
		problems.Err("Claude history"),
		all.Err("Claude history"),
	)
}

// scanAndStoreClaudePrompts folds any not-yet-recorded Claude prompts for this
// repository into the local registry. It is best-effort and repo-scoped, and it
// never imports history from before this project was cloned.
func scanAndStoreClaudePrompts(repo RepositoryInfo) (int, error) {
	if !repo.Project.LocalStore || !repo.Project.toolEnabled(model.ToolClaudeCode) {
		return 0, nil
	}
	added := 0
	err := withProviderScanLock(repo.Root, model.ToolClaudeCode, func() error {
		state, err := loadProviderScanState(repo.Root, model.ToolClaudeCode)
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
		if adoptErr := adoptAuthoritativeRecoverySnapshot(
			repo.Root,
			dedupeStoreSet,
			&state,
		); adoptErr != nil {
			return adoptErr
		}
		anchor := cloneAnchorTime(repo.Root)
		buildHistoryEvent := func(prompt scannedPrompt) model.Event {
			return model.Event{
				EventID:   claudeHistoryEventID(prompt.SessionID, prompt.Position, prompt.Timestamp),
				Timestamp: prompt.Timestamp,
				Tool:      model.ToolClaudeCode,
				SessionID: prompt.SessionID,
				Prompt:    boundRedactedPrompt(redactor.Redact(prompt.Prompt)),
			}
		}
		exactHistoryIDs := reserveExactHistoryIDs(
			existing,
			model.ToolClaudeCode,
			buildHistoryEvent,
			func(observe func(scannedPrompt) bool) error {
				reservationState := emptyProviderScanState()
				_, _, err := scanClaudePromptsFiltered(
					repo.Root,
					&reservationState,
					observe,
					nil,
				)
				return err
			},
		)
		if pruneHistoryAliases(&state, existing, exactHistoryIDs) {
			state.Files = map[string]scanFingerprint{}
			state.Cursors = map[string]scanCursor{}
		}
		reservedHistoryIDs := cloneHistoryIDReservations(exactHistoryIDs)
		for _, targetID := range state.HistoryAliases {
			reservedHistoryIDs[targetID] = true
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
		deduper.SetExactObserver(func(eventID string) {
			exactHistoryIDs[eventID] = true
			reservedHistoryIDs[eventID] = true
		})
		deduper.AddHistoryAliases(state.HistoryAliases)
		skipKnown := func(prompt scannedPrompt) bool {
			if !anchor.IsZero() && prompt.Timestamp.Before(anchor) {
				return true
			}
			return deduper.Skip(prompt)
		}
		prompts, pendingBatch, scanErr := scanClaudePromptsFiltered(
			repo.Root,
			&state,
			skipKnown,
			deduper.ObserveExact,
		)
		if pruneHistoryAliases(&state, existing, exactHistoryIDs) {
			state.Files = map[string]scanFingerprint{}
			state.Cursors = map[string]scanCursor{}
			pendingBatch = true
		}
		_, email, _ := automaticIdentity(repo.Root)
		userID := localUserID(email)
		events := make([]model.Event, 0, len(prompts))
		for _, prompt := range prompts {
			if !anchor.IsZero() && prompt.Timestamp.Before(anchor) {
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
		if !canPersistHistoryAliasCandidates(state, events) {
			reserveAllExistingHistoryIDs(existing, model.ToolClaudeCode, reservedHistoryIDs)
		}
		var historyAliases map[string]string
		var storeErr error
		added, historyAliases, storeErr = appendNewLocalEventsDetailed(
			repo.Root,
			userID,
			events,
			reservedHistoryIDs,
		)
		if storeErr != nil {
			return errors.Join(scanErr, storeErr)
		}
		if aliasErr := mergeHistoryAliases(&state, historyAliases); aliasErr != nil {
			return errors.Join(scanErr, aliasErr)
		}
		storeSetSafe, stateErr := revalidateScanStateStoreSet(
			repo.Root,
			dedupeStoreSet,
			&state,
		)
		if stateErr != nil {
			return errors.Join(scanErr, stateErr)
		}
		if !storeSetSafe {
			pendingBatch = true
		}
		stateErr = saveProviderScanState(repo.Root, model.ToolClaudeCode, state)
		var pendingErr error
		if pendingBatch {
			pendingErr = errProviderRecoveryPending
		}
		return errors.Join(scanErr, stateErr, pendingErr)
	})
	return added, err
}
