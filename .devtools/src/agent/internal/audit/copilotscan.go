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
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

// GitHub Copilot Chat in VS Code writes sessions to a local transcript at
//   <workspaceStorage>/<hash>/GitHub.copilot-chat/transcripts/<session>.jsonl
// The transcript records carry no cwd, but each workspace-storage folder has a
// sibling workspace.json whose "folder" URI names the project that owns it.
// Resolving that mapping provides a recovery path for supported VS Code
// sessions. Copilot CLI itself is captured by its direct repository or policy
// hook; this scanner does not claim to cover every Copilot surface.
//
// Only "user.message" records are eligible for storage (the text the worker
// typed); assistant turns, tool calls and telemetry are ignored.

type copilotRecord struct {
	Type      string          `json:"type"`
	Timestamp string          `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

type copilotUserData struct {
	Content *string `json:"content"`
}

const maxCopilotWorkspaceMetadataBytes = 256 * 1024

// copilotStorageRoots returns the VS Code (stable, Insiders and VSCodium)
// workspaceStorage directories that exist on this machine.
func copilotStorageRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var bases []string
	switch runtime.GOOS {
	case "windows":
		appData := strings.TrimSpace(os.Getenv("APPDATA"))
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		bases = []string{
			filepath.Join(appData, "Code", "User", "workspaceStorage"),
			filepath.Join(appData, "Code - Insiders", "User", "workspaceStorage"),
			filepath.Join(appData, "VSCodium", "User", "workspaceStorage"),
		}
	case "darwin":
		support := filepath.Join(home, "Library", "Application Support")
		bases = []string{
			filepath.Join(support, "Code", "User", "workspaceStorage"),
			filepath.Join(support, "Code - Insiders", "User", "workspaceStorage"),
			filepath.Join(support, "VSCodium", "User", "workspaceStorage"),
		}
	default:
		config := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
		if config == "" {
			config = filepath.Join(home, ".config")
		}
		bases = []string{
			filepath.Join(config, "Code", "User", "workspaceStorage"),
			filepath.Join(config, "Code - Insiders", "User", "workspaceStorage"),
			filepath.Join(config, "VSCodium", "User", "workspaceStorage"),
		}
	}
	var existing []string
	for _, base := range bases {
		if info, err := os.Stat(base); err == nil && info.IsDir() {
			existing = append(existing, base)
		}
	}
	return existing
}

// copilotHistoryEventID combines session, physical line and provider timestamp,
// so repaired or inserted rows cannot steal an existing prompt ID.
func copilotHistoryEventID(sessionID string, position int, timestamp time.Time) string {
	sum := sha256.Sum256([]byte(
		"copilot-history-v2\x00" + sessionID + "\x00" + strconv.Itoa(position) +
			"\x00" + timestamp.UTC().Format(time.RFC3339Nano),
	))
	return "copilot-h-" + hex.EncodeToString(sum[:16])
}

// decodeWorkspaceFolderURI turns a VS Code "file://" folder URI into a native
// path (e.g. file:///c%3A/Users/x → C:\Users\x).
func decodeWorkspaceFolderURI(uri string) string {
	uri = strings.TrimSpace(uri)
	if !strings.HasPrefix(uri, "file://") {
		return ""
	}
	rest := strings.TrimPrefix(uri, "file://")
	decoded, err := url.PathUnescape(rest)
	if err != nil {
		return ""
	}
	if runtime.GOOS == "windows" {
		decoded = strings.TrimPrefix(decoded, "/")
		decoded = filepath.FromSlash(decoded)
	}
	return decoded
}

// copilotWorkspaceFolder reads <hash>/workspace.json and returns the decoded
// folder path that owns this workspace-storage directory.
func copilotWorkspaceFolder(storageDir string) (string, error) {
	path := filepath.Join(storageDir, "workspace.json")
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("open Copilot workspace metadata: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat Copilot workspace metadata: %w", err)
	}
	if info.Size() > maxCopilotWorkspaceMetadataBytes {
		return "", errors.New("Copilot workspace metadata exceeds 256 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCopilotWorkspaceMetadataBytes+1))
	if err != nil {
		return "", fmt.Errorf("read Copilot workspace metadata: %w", err)
	}
	if len(data) > maxCopilotWorkspaceMetadataBytes {
		return "", errors.New("Copilot workspace metadata exceeds 256 KiB")
	}
	var meta struct {
		Folder string `json:"folder"`
	}
	if validateUniqueJSONKeys(data) != nil || json.Unmarshal(data, &meta) != nil {
		return "", errors.New("Copilot workspace metadata is invalid")
	}
	if strings.TrimSpace(meta.Folder) == "" {
		return "", nil
	}
	folder := decodeWorkspaceFolderURI(meta.Folder)
	if folder == "" {
		return "", errors.New("Copilot workspace folder URI is invalid")
	}
	return folder, nil
}

func scanCopilotFile(path, sessionID string) ([]scannedPrompt, error) {
	prompts, nextLine, err := scanCopilotFilePage(
		path,
		sessionID,
		1,
		newRecoveredPromptCollector(),
	)
	if nextLine != 0 {
		err = errors.Join(err, errProviderRecoveryPending)
	}
	return prompts, err
}

func scanCopilotFilePage(
	path,
	sessionID string,
	startLine int,
	prompts *recoveredPromptCollector,
) ([]scannedPrompt, int, error) {
	found, nextLine, _, err := scanCopilotFilePageSnapshot(
		path,
		sessionID,
		startLine,
		prompts,
		nil,
		nil,
	)
	return found, nextLine, err
}

func scanCopilotFilePageSnapshot(
	path,
	sessionID string,
	startLine int,
	prompts *recoveredPromptCollector,
	skipKnown func(scannedPrompt) bool,
	observeCandidate func(scannedPrompt),
) ([]scannedPrompt, int, scannedFileIdentity, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, 0, scannedFileIdentity{}, fmt.Errorf("open Copilot transcript: %w", err)
	}
	defer file.Close()
	snapshotReader, tracker, snapshotInfo, err := beginProviderFileSnapshot(file)
	if err != nil {
		return nil, 0, scannedFileIdentity{}, fmt.Errorf("snapshot Copilot transcript: %w", err)
	}
	if startLine < 1 {
		startLine = 1
	}

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
			problems.Add(fmt.Errorf("Copilot transcript line %d exceeds the size limit", lineNumber))
			continue
		}
		if readErr != nil {
			problems.Add(fmt.Errorf("read Copilot transcript: %w", readErr))
			break
		}
		if len(line) == 0 {
			continue
		}
		var record copilotRecord
		if !isJSONObject(line) ||
			validateUniqueJSONKeys(line) != nil ||
			json.Unmarshal(line, &record) != nil ||
			strings.TrimSpace(record.Type) == "" {
			problems.Add(fmt.Errorf("Copilot transcript contains invalid JSON on line %d", lineNumber))
			continue
		}
		if record.Type != "user.message" {
			continue
		}
		var data copilotUserData
		if !isJSONObject(record.Data) || json.Unmarshal(record.Data, &data) != nil || data.Content == nil {
			problems.Add(fmt.Errorf("Copilot user event is invalid on line %d", lineNumber))
			continue
		}
		if strings.TrimSpace(*data.Content) == "" {
			continue
		}
		timestamp := parseCodexTimestamp(record.Timestamp)
		if timestamp.IsZero() {
			problems.Add(fmt.Errorf("Copilot user event has no valid timestamp on line %d", lineNumber))
			continue
		}
		candidate := scannedPrompt{
			SessionID: sessionID,
			Position:  lineNumber,
			Prompt:    *data.Content,
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
		problems.Err("Copilot transcript"),
		prompts.Err("Copilot transcript"),
		identityErr,
	)
}

func scanCopilotPrompts(
	repoRoot string,
	state *providerScanState,
) ([]scannedPrompt, bool, error) {
	return scanCopilotPromptsFiltered(repoRoot, state, nil, nil)
}

func scanCopilotPromptsFiltered(
	repoRoot string,
	state *providerScanState,
	skipKnown func(scannedPrompt) bool,
	observeCandidate func(scannedPrompt),
) ([]scannedPrompt, bool, error) {
	roots := copilotStorageRoots()
	if len(roots) == 0 {
		return nil, false, nil
	}
	// See transcriptPredatesClone: a transcript last written before this clone
	// existed cannot hold a prompt that belongs to it.
	anchor := cloneAnchorTime(repoRoot)
	all := newRecoveredPromptCollector()
	var problems problemCollector
	pendingBatch := false
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			problems.Add(fmt.Errorf("read Copilot workspace storage: %w", err))
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			storageDir := filepath.Join(root, entry.Name())
			folder, folderErr := copilotWorkspaceFolder(storageDir)
			if folderErr != nil {
				problems.Add(folderErr)
				continue
			}
			folderScope := classifyProviderCWD(folder, repoRoot)
			if folderScope == providerPathIndeterminate {
				problems.Add(fmt.Errorf("Copilot workspace folder cannot be verified"))
				continue
			}
			if folderScope != providerPathInside {
				continue
			}
			transcripts := filepath.Join(storageDir, "GitHub.copilot-chat", "transcripts")
			if _, err := os.Stat(transcripts); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				problems.Add(fmt.Errorf("inspect Copilot transcripts: %w", err))
				continue
			}
			walkErr := filepath.WalkDir(transcripts, func(path string, item fs.DirEntry, walkError error) error {
				if walkError != nil {
					problems.Add(fmt.Errorf("walk Copilot transcripts: %w", walkError))
					return nil
				}
				if item.IsDir() || !strings.HasSuffix(path, ".jsonl") {
					return nil
				}
				info, err := item.Info()
				if err != nil {
					problems.Add(fmt.Errorf("stat Copilot transcript: %w", err))
					return nil
				}
				if transcriptPredatesClone(info, anchor) {
					return nil
				}
				unchanged, unchangedErr := scanStateUnchanged(
					*state,
					model.ToolCopilotCLI,
					path,
					info,
				)
				if unchangedErr != nil {
					problems.Add(fmt.Errorf("authenticate Copilot transcript state: %w", unchangedErr))
					return nil
				}
				if unchanged {
					return nil
				}
				sessionID := strings.TrimSuffix(filepath.Base(path), ".jsonl")
				startLine, cursorErr := scanStartLine(state, model.ToolCopilotCLI, path, info)
				if cursorErr != nil {
					problems.Add(cursorErr)
					return nil
				}
				var resumedCursor *scanCursor
				if startLine > 1 {
					cursor := state.Cursors[scanStateKey(model.ToolCopilotCLI, path)]
					resumedCursor = &cursor
				}
				prompts, nextLine, snapshot, scanErr := scanCopilotFilePageSnapshot(
					path,
					sessionID,
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
					delete(state.Cursors, scanStateKey(model.ToolCopilotCLI, path))
					pendingBatch = true
					if verifyErr != nil {
						problems.Add(fmt.Errorf("verify Copilot transcript snapshot: %w", verifyErr))
					}
					return nil
				}
				if resumedCursor != nil && !cursorMatches {
					delete(state.Cursors, scanStateKey(model.ToolCopilotCLI, path))
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
						model.ToolCopilotCLI,
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
						model.ToolCopilotCLI,
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
		}
	}
	return all.Values(), pendingBatch, errors.Join(
		problems.Err("Copilot history"),
		all.Err("Copilot history"),
	)
}

// scanAndStoreCopilotPrompts folds any not-yet-recorded Copilot prompts for this
// repository into the local registry. Best-effort, repo-scoped, and never
// imports history from before this project was cloned.
func scanAndStoreCopilotPrompts(repo RepositoryInfo) (int, error) {
	if !repo.Project.LocalStore || !repo.Project.toolEnabled(model.ToolCopilotCLI) {
		return 0, nil
	}
	added := 0
	err := withProviderScanLock(repo.Root, model.ToolCopilotCLI, func() error {
		state, err := loadProviderScanState(repo.Root, model.ToolCopilotCLI)
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
				EventID:   copilotHistoryEventID(prompt.SessionID, prompt.Position, prompt.Timestamp),
				Timestamp: prompt.Timestamp,
				Tool:      model.ToolCopilotCLI,
				SessionID: prompt.SessionID,
				Prompt:    boundRedactedPrompt(redactor.Redact(prompt.Prompt)),
			}
		}
		exactHistoryIDs := reserveExactHistoryIDs(
			existing,
			model.ToolCopilotCLI,
			buildHistoryEvent,
			func(observe func(scannedPrompt) bool) error {
				reservationState := emptyProviderScanState()
				_, _, err := scanCopilotPromptsFiltered(
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
		prompts, pendingBatch, scanErr := scanCopilotPromptsFiltered(
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
			reserveAllExistingHistoryIDs(existing, model.ToolCopilotCLI, reservedHistoryIDs)
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
		stateErr = saveProviderScanState(repo.Root, model.ToolCopilotCLI, state)
		var pendingErr error
		if pendingBatch {
			pendingErr = errProviderRecoveryPending
		}
		return errors.Join(scanErr, stateErr, pendingErr)
	})
	return added, err
}
