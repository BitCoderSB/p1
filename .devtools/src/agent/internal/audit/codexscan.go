package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

// Codex writes sessions to local rollout logs. This scanner is a recovery path
// for gaps in the direct UserPromptSubmit hook; it remains project-scoped and
// never treats transcript scanning as proof that the project hook was trusted
// or active. Only user-message records are eligible for storage; assistant
// output is discarded.
//
// The log format (JSONL) is treated as versioned input: a "session_meta" record
// carries the session id and cwd; an "event_msg" record whose payload type is
// "user_message" carries one user prompt. Subagent / forked sessions are skipped
// so internal tool prompts never leak into the registry.

type codexRecord struct {
	Type      string          `json:"type"`
	Timestamp string          `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

type codexSessionMeta struct {
	ID             string  `json:"id"`
	CWD            string  `json:"cwd"`
	CLIVersion     string  `json:"cli_version"`
	ThreadSource   *string `json:"thread_source"`
	ParentThreadID string  `json:"parent_thread_id"`
	ForkedFromID   string  `json:"forked_from_id"`
	AgentPath      string  `json:"agent_path"`
	// Codex writes "source" as a plain string in real sessions but as an object
	// in some builds. Keep it raw and inspect it only when it is an object, so a
	// string value never fails the whole session_meta parse.
	Source json.RawMessage `json:"source"`
}

type codexUserMessage struct {
	Type      string  `json:"type"`
	Message   *string `json:"message"`
	Timestamp string  `json:"timestamp"`
}

type scannedPrompt struct {
	SessionID string
	Position  int
	Prompt    string
	Timestamp time.Time
}

// Recovery accepts no larger physical input unit than the direct hook envelope.
// Oversized lines are discarded in bounded chunks and scanning resumes.
const maxProviderTranscriptLineBytes = maxHookInputBytes

func codexSessionsRoot() string {
	if home := strings.TrimSpace(os.Getenv("CODEX_HOME")); home != "" {
		return filepath.Join(home, "sessions")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".codex", "sessions")
}

// codexHistoryEventID combines session, physical line and provider timestamp.
// Line position survives malformed-row repair; timestamp prevents an inserted
// row from inheriting the ID previously assigned at that position.
func codexHistoryEventID(sessionID string, position int, timestamp time.Time) string {
	sum := sha256.Sum256([]byte(
		"codex-history-v2\x00" + sessionID + "\x00" + strconv.Itoa(position) +
			"\x00" + timestamp.UTC().Format(time.RFC3339Nano),
	))
	return "codex-h-" + hex.EncodeToString(sum[:16])
}

func codexSessionCapturable(meta codexSessionMeta) bool {
	// Fail closed on legacy or future metadata that does not explicitly identify
	// a human/root thread. Current Codex emits both thread_source and source.
	if !codexRecoveryVersionAtLeast(meta.CLIVersion, 0, 134, 0) {
		return false
	}
	if meta.ThreadSource == nil || *meta.ThreadSource != "user" {
		return false
	}
	if meta.ParentThreadID != "" {
		return false
	}
	if meta.ForkedFromID != "" {
		return false
	}
	if meta.AgentPath != "" {
		return false
	}
	var sourceName string
	if json.Unmarshal(meta.Source, &sourceName) != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(sourceName)) {
	case "cli", "vscode", "exec", "mcp":
		return true
	default:
		// Custom, unknown, internal, subagent, and any future source require an
		// explicit review before they can become prompt-capture inputs.
		return false
	}
}

func codexSessionExplicitlyNonRoot(meta codexSessionMeta) bool {
	if strings.TrimSpace(meta.ParentThreadID) != "" ||
		strings.TrimSpace(meta.ForkedFromID) != "" ||
		strings.TrimSpace(meta.AgentPath) != "" {
		return true
	}
	var sourceObject map[string]json.RawMessage
	if json.Unmarshal(meta.Source, &sourceObject) == nil {
		for _, key := range []string{
			"agent_path",
			"forked_from_id",
			"internal",
			"parent_thread_id",
			"subagent",
		} {
			if _, exists := sourceObject[key]; exists {
				return true
			}
		}
	}
	if meta.ThreadSource == nil {
		return false
	}
	threadSource := strings.TrimSpace(*meta.ThreadSource)
	if threadSource != "" && threadSource != "user" {
		return true
	}
	var sourceName string
	if json.Unmarshal(meta.Source, &sourceName) == nil {
		switch strings.ToLower(strings.TrimSpace(sourceName)) {
		case "agent", "internal", "memory_consolidation", "subagent":
			return true
		}
	}
	return false
}

func codexSessionMetaStructurallyValid(meta codexSessionMeta) bool {
	if meta.ID == "" || meta.ID != strings.TrimSpace(meta.ID) {
		return false
	}
	if strings.TrimSpace(meta.CWD) == "" || strings.TrimSpace(meta.CLIVersion) == "" {
		return false
	}
	if meta.ThreadSource == nil || strings.TrimSpace(*meta.ThreadSource) == "" {
		return false
	}
	rawSource := strings.TrimSpace(string(meta.Source))
	return rawSource != "" && rawSource != "null"
}

func normalizeForCompare(path string) string {
	clean := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		return strings.ToLower(clean)
	}
	return clean
}

func canonicalPathForCompare(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
		absolute = resolved
	}
	return normalizeForCompare(absolute)
}

func sameCanonicalPath(left, right string) bool {
	canonicalLeft := canonicalPathForCompare(left)
	canonicalRight := canonicalPathForCompare(right)
	return canonicalLeft != "" && canonicalRight != "" && canonicalLeft == canonicalRight
}

// pathInRepo reports whether a Codex session cwd sits inside this repository's
// directory tree.
func pathInRepo(cwd, repoRoot string) bool {
	if strings.TrimSpace(cwd) == "" {
		return false
	}
	canonicalRoot := canonicalPathForCompare(repoRoot)
	canonicalCWD := canonicalPathForCompare(cwd)
	if canonicalRoot == "" || canonicalCWD == "" {
		return false
	}
	rel, err := filepath.Rel(canonicalRoot, canonicalCWD)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

type providerPathScope uint8

const (
	providerPathOutside providerPathScope = iota
	providerPathInside
	providerPathIndeterminate
)

func lexicalPathInRepo(path, repoRoot string) bool {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absoluteRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return false
	}
	cleanPath := normalizeForCompare(absolutePath)
	cleanRoot := normalizeForCompare(absoluteRoot)
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// codexCwdBelongsToRepo reports whether a Codex session's cwd belongs to THIS
// repository — the root or one of its own subfolders — and not to a different,
// nested Git repository living inside it (e.g. a checked-in reference project).
// Only prompts sent from this project's own tree are ever captured.
func classifyProviderCWD(cwd, repoRoot string) providerPathScope {
	if cwd == "" || cwd != strings.TrimSpace(cwd) || !filepath.IsAbs(cwd) {
		return providerPathOutside
	}
	rootInfo, err := os.Stat(repoRoot)
	if err != nil || !rootInfo.IsDir() {
		return providerPathIndeterminate
	}
	resolvedRoot, err := resolvePathThroughExistingAncestor(repoRoot)
	if err != nil {
		return providerPathIndeterminate
	}
	cwdInfo, err := os.Stat(cwd)
	if err != nil || !cwdInfo.IsDir() {
		if lexicalPathInRepo(cwd, resolvedRoot) {
			return providerPathIndeterminate
		}
		return providerPathOutside
	}
	resolvedCWD, err := resolvePathThroughExistingAncestor(cwd)
	if err != nil {
		if lexicalPathInRepo(cwd, resolvedRoot) {
			return providerPathIndeterminate
		}
		return providerPathOutside
	}
	if !pathInRepo(resolvedCWD, resolvedRoot) {
		return providerPathOutside
	}
	root := canonicalPathForCompare(resolvedRoot)
	current := canonicalPathForCompare(resolvedCWD)
	if root == "" || current == "" {
		return providerPathIndeterminate
	}
	for {
		if current == root {
			return providerPathInside
		}
		// A .git between the cwd and the repo root marks a nested repository;
		// its prompts belong to that project, not this one.
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return providerPathOutside
		} else if !errors.Is(err, os.ErrNotExist) {
			// An unreadable or otherwise indeterminate repository marker is not
			// safe to treat as part of the parent project.
			return providerPathIndeterminate
		}
		parent := filepath.Dir(current)
		if normalizeForCompare(parent) == current {
			return providerPathOutside
		}
		current = normalizeForCompare(parent)
	}
}

func codexCwdBelongsToRepo(cwd, repoRoot string) bool {
	return classifyProviderCWD(cwd, repoRoot) == providerPathInside
}

func parseCodexTimestamp(values ...string) time.Time {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed.UTC()
			}
		}
	}
	return time.Time{}
}

func scanCodexFile(path, repoRoot string) ([]scannedPrompt, error) {
	return scanCodexFileWithLineLimit(path, repoRoot, maxProviderTranscriptLineBytes)
}

func scanCodexFileWithLineLimit(path, repoRoot string, maxLineBytes int) ([]scannedPrompt, error) {
	prompts, nextLine, err := scanCodexFilePage(
		path,
		repoRoot,
		maxLineBytes,
		1,
		newRecoveredPromptCollector(),
	)
	if nextLine != 0 {
		err = errors.Join(err, errProviderRecoveryPending)
	}
	return prompts, err
}

func scanCodexFilePage(
	path,
	repoRoot string,
	maxLineBytes,
	startLine int,
	prompts *recoveredPromptCollector,
) ([]scannedPrompt, int, error) {
	found, nextLine, _, err := scanCodexFilePageSnapshot(
		path,
		repoRoot,
		maxLineBytes,
		startLine,
		prompts,
		nil,
		nil,
	)
	return found, nextLine, err
}

func scanCodexFilePageSnapshot(
	path,
	repoRoot string,
	maxLineBytes,
	startLine int,
	prompts *recoveredPromptCollector,
	skipKnown func(scannedPrompt) bool,
	observeCandidate func(scannedPrompt),
) ([]scannedPrompt, int, scannedFileIdentity, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, 0, scannedFileIdentity{}, fmt.Errorf("open Codex session: %w", err)
	}
	defer file.Close()
	snapshotReader, tracker, snapshotInfo, err := beginProviderFileSnapshot(file)
	if err != nil {
		return nil, 0, scannedFileIdentity{}, fmt.Errorf("snapshot Codex session: %w", err)
	}
	if startLine < 1 {
		startLine = 1
	}

	reader := bufio.NewReaderSize(snapshotReader, providerLineBufferSize(maxLineBytes))
	var sessionID string
	matched := false
	eligible := false
	// A corrupt row can hide a metadata transition. Keep such problems pending
	// while a rollout is scoped only to other repositories; if the same file
	// later identifies this repository, materialize a bounded diagnostic and
	// poison the file so no prompt after the ambiguous transition is accepted.
	var pendingProblem error
	var pendingAdditional uint64
	poisoned := false
	var problems problemCollector
	lineNumber := 0
	nextLine := 0
	markCorrupt := func(problem error) {
		if matched && !poisoned {
			problems.Add(problem)
			poisoned = true
		} else if !poisoned {
			if pendingProblem == nil {
				pendingProblem = problem
			} else if pendingAdditional != ^uint64(0) {
				pendingAdditional++
			}
		}
		// The bad row itself could have been session metadata. Require another
		// valid metadata record before even establishing repository scope.
		matched = false
		eligible = false
	}
	for {
		line, eof, readErr := readBoundedProviderLine(reader, maxLineBytes)
		if eof {
			break
		}
		lineNumber++
		if errors.Is(readErr, errProviderLineTooLong) {
			// The line has been discarded through its terminator, so scanning
			// can continue and a later repo metadata record can materialize the
			// otherwise unscoped corruption.
			markCorrupt(fmt.Errorf("Codex session line %d exceeds the size limit", lineNumber))
			continue
		}
		if readErr != nil {
			// Unlike a recoverable oversized row, an actual I/O failure leaves
			// the remainder unknowable. Surface it regardless of current scope.
			problems.Add(fmt.Errorf("read Codex session: %w", readErr))
			break
		}
		if len(line) == 0 {
			continue
		}
		var record codexRecord
		if !isJSONObject(line) ||
			validateUniqueJSONKeys(line) != nil ||
			json.Unmarshal(line, &record) != nil ||
			strings.TrimSpace(record.Type) == "" {
			// Codex keeps every workspace under one global sessions root. A
			// corrupt row in a file that remains foreign must not make this
			// project's explicit recovery unhealthy. Keep its error pending,
			// though: the same rollout can later transition into this repo.
			markCorrupt(fmt.Errorf("Codex session contains invalid JSON on line %d", lineNumber))
			continue
		}
		switch record.Type {
		case "session_meta":
			var meta codexSessionMeta
			if json.Unmarshal(record.Payload, &meta) != nil {
				markCorrupt(fmt.Errorf("Codex session metadata is invalid on line %d", lineNumber))
				continue
			}
			metaScope := classifyProviderCWD(meta.CWD, repoRoot)
			metaMatchesRepo := metaScope == providerPathInside
			metaScopeIndeterminate := metaScope == providerPathIndeterminate
			if codexSessionExplicitlyNonRoot(meta) {
				// Forked rollouts can embed root metadata and prompts before the
				// explicit provenance marker. Once that marker appears, discard
				// everything accumulated from this physical file.
				_, drainErr := io.Copy(io.Discard, reader)
				identity, identityErr := finishProviderFileSnapshot(tracker, snapshotInfo)
				return nil, 0, identity, errors.Join(drainErr, identityErr)
			}
			if !codexSessionMetaStructurallyValid(meta) {
				// Preserve an already established repo scope when malformed
				// metadata has no usable cwd. If its cwd does point here, make
				// the corruption immediately relevant even when required fields
				// such as the session id are missing.
				if metaMatchesRepo || metaScopeIndeterminate {
					matched = true
					eligible = true
				}
				markCorrupt(fmt.Errorf("Codex session metadata is incomplete on line %d", lineNumber))
				continue
			}
			// A rollout can contain more than one metadata record (for example,
			// after a fork or workspace change). Scope every following prompt to
			// the most recent cwd and session id instead of trusting the first
			// record forever.
			sessionID = meta.ID
			matched = metaMatchesRepo || metaScopeIndeterminate
			eligible = metaMatchesRepo && codexSessionCapturable(meta)
			if metaScopeIndeterminate {
				problems.Add(
					fmt.Errorf("Codex session cwd cannot be verified on line %d", lineNumber),
				)
				poisoned = true
			} else if matched && !eligible {
				problems.Add(
					fmt.Errorf(
						"Codex session metadata is not a supported root user session on line %d",
						lineNumber,
					),
				)
				poisoned = true
			}
			if matched && pendingProblem != nil {
				problems.Add(pendingProblem)
				if pendingAdditional != 0 {
					problems.Add(
						fmt.Errorf(
							"Codex session contains %d additional corrupt rows before repository scope",
							pendingAdditional,
						),
					)
				}
				pendingProblem = nil
				pendingAdditional = 0
				poisoned = true
			}
		case "event_msg":
			if !eligible || poisoned || sessionID == "" {
				continue
			}
			var message codexUserMessage
			if !isJSONObject(record.Payload) ||
				json.Unmarshal(record.Payload, &message) != nil ||
				strings.TrimSpace(message.Type) == "" {
				problems.Add(fmt.Errorf("Codex user event is invalid on line %d", lineNumber))
				continue
			}
			if message.Type != "user_message" {
				continue
			}
			if message.Message == nil {
				problems.Add(fmt.Errorf("Codex user event has no message on line %d", lineNumber))
				continue
			}
			if strings.TrimSpace(*message.Message) == "" {
				continue
			}
			timestamp := parseCodexTimestamp(record.Timestamp, message.Timestamp)
			if timestamp.IsZero() {
				problems.Add(fmt.Errorf("Codex user event has no valid timestamp on line %d", lineNumber))
				continue
			}
			candidate := scannedPrompt{
				SessionID: sessionID,
				Position:  lineNumber,
				Prompt:    *message.Message,
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
	}
	identity, identityErr := finishProviderFileSnapshot(tracker, snapshotInfo)
	return prompts.Values(), nextLine, identity, errors.Join(
		problems.Err("Codex session"),
		prompts.Err("Codex session"),
		identityErr,
	)
}

func scanCodexPrompts(
	repoRoot string,
	state *providerScanState,
) ([]scannedPrompt, bool, error) {
	return scanCodexPromptsWithCollectorFactory(
		repoRoot,
		state,
		newRecoveredPromptCollector,
	)
}

func scanCodexPromptsWithCollectorFactory(
	repoRoot string,
	state *providerScanState,
	newCollector func() *recoveredPromptCollector,
) ([]scannedPrompt, bool, error) {
	return scanCodexPromptsWithCollectorFactoryAndFilter(
		repoRoot,
		state,
		newCollector,
		nil,
		nil,
	)
}

func scanCodexPromptsWithCollectorFactoryAndFilter(
	repoRoot string,
	state *providerScanState,
	newCollector func() *recoveredPromptCollector,
	skipKnown func(scannedPrompt) bool,
	observeCandidate func(scannedPrompt),
) ([]scannedPrompt, bool, error) {
	root := codexSessionsRoot()
	if root == "" {
		return nil, false, nil
	}
	if _, err := os.Stat(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("inspect Codex sessions directory: %w", err)
	}
	// Only prompts written after this clone existed can belong to it, and a
	// transcript whose last write predates the clone cannot contain one. Deciding
	// that from the directory entry avoids opening the file at all, which is the
	// difference between reading a worker's entire multi-gigabyte Codex history
	// and reading the handful of sessions that could possibly matter.
	anchor := cloneAnchorTime(repoRoot)
	all := newCollector()
	var problems problemCollector
	pendingBatch := false
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkError error) error {
		if walkError != nil {
			problems.Add(fmt.Errorf("walk Codex sessions: %w", walkError))
			return nil
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			problems.Add(fmt.Errorf("stat Codex session: %w", err))
			return nil
		}
		if transcriptPredatesClone(info, anchor) {
			return nil
		}
		unchanged, unchangedErr := scanStateUnchanged(
			*state,
			model.ToolCodex,
			path,
			info,
		)
		if unchangedErr != nil {
			problems.Add(fmt.Errorf("authenticate Codex session state: %w", unchangedErr))
			return nil
		}
		if unchanged {
			return nil
		}
		startLine, cursorErr := scanStartLine(state, model.ToolCodex, path, info)
		if cursorErr != nil {
			problems.Add(cursorErr)
			return nil
		}
		var resumedCursor *scanCursor
		if startLine > 1 {
			cursor := state.Cursors[scanStateKey(model.ToolCodex, path)]
			resumedCursor = &cursor
		}
		prompts, nextLine, snapshot, scanErr := scanCodexFilePageSnapshot(
			path,
			repoRoot,
			maxProviderTranscriptLineBytes,
			startLine,
			newCollector(),
			skipKnown,
			observeCandidate,
		)
		matches, grew, cursorMatches, verifyErr := verifyScannedFileIdentity(
			path,
			snapshot,
			resumedCursor,
		)
		if verifyErr != nil || !matches {
			delete(state.Cursors, scanStateKey(model.ToolCodex, path))
			pendingBatch = true
			if verifyErr != nil {
				problems.Add(fmt.Errorf("verify Codex session snapshot: %w", verifyErr))
			}
			return nil
		}
		if resumedCursor != nil && !cursorMatches {
			delete(state.Cursors, scanStateKey(model.ToolCodex, path))
			pendingBatch = true
			return nil
		}
		buffered := all.AddAll(prompts)
		if scanErr != nil {
			problems.Add(
				fmt.Errorf("scan Codex session %s: %w", filepath.Base(path), scanErr),
			)
			return nil
		}
		if !buffered {
			pendingBatch = true
			return nil
		}
		if nextLine != 0 {
			if cursorErr := updateScanCursor(
				state,
				model.ToolCodex,
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
				model.ToolCodex,
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
		problems.Err("Codex history"),
		all.Err("Codex history"),
	)
}

// transcriptPredatesClone reports whether a transcript can be skipped without
// opening it. Records are appended in time order, so the file's last write is
// no earlier than its newest record: if that write happened before this clone
// existed, no record inside it can belong to this clone.
//
// The same clock-skew margin the anchor itself uses is applied, and an
// unavailable or zero timestamp always means "do not skip" — a cheap
// optimisation must never be able to hide a prompt.
func transcriptPredatesClone(info fs.FileInfo, anchor time.Time) bool {
	if anchor.IsZero() || info == nil {
		return false
	}
	modified := info.ModTime()
	if modified.IsZero() {
		return false
	}
	return modified.Before(anchor.Add(-cloneAnchorClockSkew))
}

// cloneAnchorFileName stores, per clone, the timestamp before which Codex
// history must never be imported. It lives in the git-ignored backup so every
// clone anchors to its own clone time and the value stays stable across clears.
const cloneAnchorFileName = ".since"

const (
	maxCloneAnchorBytes  = 128
	cloneAnchorClockSkew = 5 * time.Minute
)

// cloneAnchorTime returns the moment this working copy came into existence, so
// only prompts sent after the project was cloned are ever recorded. It is the
// oldest Git reflog entry (the clone/init), falling back to the .git creation
// time and then its modification time. The result is cached per clone.
func cloneAnchorTime(repoRoot string) time.Time {
	directory := localStoreDir(repoRoot)
	cache := filepath.Join(directory, cloneAnchorFileName)
	now := time.Now().UTC()
	if err := validateDirectoryTree(repoRoot, directory); err == nil {
		if parsed, err := readCloneAnchor(cache); err == nil &&
			!parsed.After(now.Add(cloneAnchorClockSkew)) {
			return parsed
		}
	}
	anchor := computeCloneAnchor(repoRoot)
	if anchor.After(now.Add(cloneAnchorClockSkew)) {
		// A filesystem timestamp far in the future would suppress real prompts.
		// Falling back to the current time is conservative for clone scoping.
		anchor = now
	}
	if !anchor.IsZero() {
		_ = persistCloneAnchor(repoRoot, cache, anchor)
	}
	return anchor
}

func readCloneAnchor(path string) (time.Time, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return time.Time{}, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxCloneAnchorBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return time.Time{}, readErr
	}
	if closeErr != nil {
		return time.Time{}, closeErr
	}
	if len(data) > maxCloneAnchorBytes {
		return time.Time{}, errors.New("clone anchor is too large")
	}
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}, errors.New("clone anchor is invalid")
	}
	return parsed.UTC(), nil
}

func persistCloneAnchor(repoRoot, path string, anchor time.Time) error {
	directory := filepath.Dir(path)
	if err := ensureDirectoryDurableUnder(repoRoot, directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".since-*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := io.WriteString(file, anchor.UTC().Format(time.RFC3339Nano)); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := protectFile(repoRoot, tmp); err != nil {
		return err
	}
	if err := validateDirectoryTree(repoRoot, directory); err != nil {
		return err
	}
	if err := replaceFile(tmp, path); err != nil {
		return err
	}
	if _, err := regularFileInfo(path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func computeCloneAnchor(repoRoot string) time.Time {
	if anchor, ok := oldestReflogTime(repoRoot); ok {
		return anchor
	}
	if anchor, ok := fileBirthTime(filepath.Join(repoRoot, ".git")); ok {
		return anchor
	}
	if info, err := os.Stat(filepath.Join(repoRoot, ".git")); err == nil {
		return info.ModTime().UTC()
	}
	return time.Time{}
}

// oldestReflogTime parses the timestamp of the oldest HEAD reflog entry, which
// is the "clone: from …" (or initial commit) record.
func oldestReflogTime(repoRoot string) (time.Time, bool) {
	out, err := gitOutput(repoRoot, "reflog", "--date=unix")
	if err != nil {
		return time.Time{}, false
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		open := strings.Index(lines[i], "@{")
		if open < 0 {
			continue
		}
		close := strings.Index(lines[i][open:], "}")
		if close < 0 {
			continue
		}
		inner := strings.TrimPrefix(lines[i][open+2:open+close], "unix:")
		seconds, err := strconv.ParseInt(strings.TrimSpace(inner), 10, 64)
		if err != nil {
			continue
		}
		return time.Unix(seconds, 0).UTC(), true
	}
	return time.Time{}, false
}

// scanAndStoreCodexPrompts folds any not-yet-recorded Codex prompts for this
// repository into the local registry. It is best-effort and repo-scoped, and it
// never imports history from before this project was cloned.
func scanAndStoreCodexPrompts(repo RepositoryInfo) (int, error) {
	return scanAndStoreCodexPromptsWithCollectorFactory(
		repo,
		newRecoveredPromptCollector,
	)
}

func scanAndStoreCodexPromptsWithCollectorFactory(
	repo RepositoryInfo,
	newCollector func() *recoveredPromptCollector,
) (int, error) {
	if !repo.Project.LocalStore || !repo.Project.toolEnabled(model.ToolCodex) {
		return 0, nil
	}
	added := 0
	err := withProviderScanLock(repo.Root, model.ToolCodex, func() error {
		state, err := loadProviderScanState(repo.Root, model.ToolCodex)
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
				EventID:   codexHistoryEventID(prompt.SessionID, prompt.Position, prompt.Timestamp),
				Timestamp: prompt.Timestamp,
				Tool:      model.ToolCodex,
				SessionID: prompt.SessionID,
				Prompt:    boundRedactedPrompt(redactor.Redact(prompt.Prompt)),
			}
		}
		exactHistoryIDs := reserveExactHistoryIDs(
			existing,
			model.ToolCodex,
			buildHistoryEvent,
			func(observe func(scannedPrompt) bool) error {
				reservationState := emptyProviderScanState()
				_, _, err := scanCodexPromptsWithCollectorFactoryAndFilter(
					repo.Root,
					&reservationState,
					newRecoveredPromptCollector,
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
		prompts, pendingBatch, scanErr := scanCodexPromptsWithCollectorFactoryAndFilter(
			repo.Root,
			&state,
			newCollector,
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
			reserveAllExistingHistoryIDs(existing, model.ToolCodex, reservedHistoryIDs)
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
		stateErr = saveProviderScanState(repo.Root, model.ToolCodex, state)
		var pendingErr error
		if pendingBatch {
			pendingErr = errProviderRecoveryPending
		}
		return errors.Join(scanErr, stateErr, pendingErr)
	})
	return added, err
}
