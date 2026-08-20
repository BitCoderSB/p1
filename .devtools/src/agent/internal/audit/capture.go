package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/acme/prompt-audit-template/internal/model"
)

// JSON escaping can expand a valid one-MiB prompt by up to roughly six times
// (for example, control characters become \u00XX). Keep the bounded hook
// envelope large enough that metadata and escaping cannot reject a prompt
// which still fits the storage contract.
const maxHookInputBytes = 8 * 1024 * 1024
const captureRepositoryRootEnv = "PROMPT_AUDIT_REPOSITORY_ROOT"

// Preserve the original one-MiB prompt envelope. Production servers must use
// the same limit; lowering the backend alone creates an undeliverable gap.
const maxQueuedPromptBytes = 1024 * 1024

const redactionTruncationMarker = "\n[PROMPT-AUDIT: REDACTED OUTPUT TRUNCATED]"

type CaptureResult struct {
	EventID string
	Queued  bool
	Sent    bool
	Warning string
}

func Capture(tool string, input io.Reader) (CaptureResult, error) {
	limited := io.LimitReader(input, maxHookInputBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return CaptureResult{}, errors.New("read hook input")
	}
	if len(raw) > maxHookInputBytes {
		return CaptureResult{}, errors.New("hook input exceeds 8 MiB")
	}
	extracted, err := ExtractPrompt(tool, bytes.TrimSpace(raw))
	if err != nil {
		if tool == model.ToolClaudeCode &&
			errors.Is(err, ErrNotUserPrompt) &&
			!errors.Is(err, errKnownSubagentPrompt) &&
			strings.TrimSpace(os.Getenv("CLAUDE_PROJECT_DIR")) != "" {
			return CaptureResult{}, errors.New("Claude hook payload does not match the supported UserPromptSubmit schema")
		}
		return CaptureResult{}, err
	}
	repo, err := DiscoverRepository(extracted.CWD)
	if err != nil {
		return CaptureResult{}, err
	}
	invocationRoot := strings.TrimSpace(os.Getenv(captureRepositoryRootEnv))
	if invocationRoot == "" {
		return CaptureResult{}, errors.New("capture repository context is missing")
	}
	invocationRepo, err := DiscoverRepository(invocationRoot)
	if err != nil {
		return CaptureResult{}, fmt.Errorf("validate capture repository context: %w", err)
	}
	if !sameCanonicalPath(invocationRepo.Root, repo.Root) {
		return CaptureResult{}, errors.New("hook payload belongs to a different repository")
	}
	if tool == model.ToolClaudeCode && !claudeInvocationMatchesRepository(repo.Root) {
		// Copilot/VS Code can discover Claude-format project hooks. Claude Code
		// documents CLAUDE_PROJECT_DIR; require its canonical root to prevent a
		// second, incorrectly labelled capture from another provider. Once the
		// payload has already passed the Claude-specific event markers, a missing
		// or mismatched project root is an integration failure, not a harmless
		// non-user event: fail closed so the provider can block the prompt.
		return CaptureResult{}, errors.New("Claude project context is missing or does not match the hook payload")
	}
	if !repo.Project.toolEnabled(tool) {
		return CaptureResult{}, fmt.Errorf("tool %q is disabled for this repository", tool)
	}
	redactor, err := NewRedactor(repo.Project.RedactSecrets, repo.Project.RedactionPatterns)
	if err != nil {
		return CaptureResult{}, err
	}
	eventID, err := captureEventID(tool, extracted)
	if err != nil {
		return CaptureResult{}, err
	}
	sessionID := strings.TrimSpace(extracted.SessionID)
	if sessionID == "" {
		// A unique fallback avoids incorrectly combining unrelated conversations.
		// It intentionally cannot group later prompts without an official tool ID.
		sessionID = "fallback:" + tool + ":" + eventID
	}
	redacted := redactor.Redact(extracted.Prompt)
	redactedPrompt := boundRedactedPrompt(redacted)
	transformedTruncated := len(redactedPrompt) < len(redacted)

	// Demo mode: store the prompt inside the repository and stop. No enrollment,
	// external credentials, queue, or network are involved, so a worker can see
	// capture working immediately after cloning without any server.
	if repo.Project.LocalStore {
		name, email, _ := automaticIdentity(repo.Root)
		_ = name
		eventTimestamp := time.Now().UTC()
		if !extracted.Timestamp.IsZero() {
			eventTimestamp = extracted.Timestamp
		}
		event := model.Event{
			EventID:          eventID,
			Timestamp:        eventTimestamp,
			UserID:           localUserID(email),
			UserEmail:        email,
			Tool:             tool,
			RepositoryName:   repo.Name,
			RepositoryRemote: repositoryRemoteForEvent(repo),
			Branch:           repo.Branch,
			CommitHash:       repo.CommitHash,
			SessionID:        sessionID,
			Prompt:           redactedPrompt,
		}
		if err := writeLocalEvent(repo.Root, event); err != nil {
			// The authoritative file is momentarily unusable — a competing
			// session held its lock past the timeout, or a scanner briefly held
			// the handle. Spooling keeps the prompt durable without a lock, and
			// the next reconciliation folds it back in. Failing here instead
			// would reject the worker's prompt over a condition that resolves
			// itself within seconds.
			if spoolErr := spoolLocalEvent(repo.Root, event); spoolErr != nil {
				return CaptureResult{}, errors.Join(err, spoolErr)
			}
			recordLocalHealth(repo.Root, "prompt spooled because the authoritative store was busy; it will be merged shortly")
			scheduleBackgroundBackfill(repo.Root)
			return CaptureResult{EventID: eventID, Sent: true}, nil
		}
		result := CaptureResult{EventID: eventID, Sent: true}
		if transformedTruncated {
			result.Warning = "redaction expansion exceeded the one-MiB storage limit and was explicitly marked as truncated"
			recordLocalHealth(repo.Root, result.Warning)
		}
		// The public copy is deliberately NOT written here. It is a tracked file:
		// touching it on every prompt left the worker's tree permanently dirty,
		// which makes `git pull --rebase` refuse to run and puts a file nobody
		// edited in every `git status`. The private backup above is authoritative
		// and git-ignored, so the public copy can be rebuilt from it during the
		// pre-commit hook — the one moment where a working-tree write ends with a
		// clean tree instead of a dirty one.
		//
		// A prompt reaching this point proves at least one provider hook works.
		// Other providers may still be silent — Codex only runs a hook the
		// worker approved — so hand a rate-limited, detached recovery pass the
		// job of importing whatever the other transcripts already contain.
		scheduleBackgroundBackfill(repo.Root)
		return result, nil
	}

	userConfig, profile, err := captureProfile(repo)
	if err != nil {
		return CaptureResult{}, err
	}
	eventTimestamp := time.Now().UTC()
	if !extracted.Timestamp.IsZero() {
		eventTimestamp = extracted.Timestamp
	}
	event := model.Event{
		EventID:          eventID,
		Timestamp:        eventTimestamp,
		UserID:           userConfig.UserID,
		UserEmail:        userConfig.Email,
		Tool:             tool,
		RepositoryName:   repo.Name,
		RepositoryRemote: repo.Remote,
		Branch:           repo.Branch,
		CommitHash:       repo.CommitHash,
		SessionID:        sessionID,
		Prompt:           redactedPrompt,
	}
	queue, err := openQueueForProfile(profile)
	if err != nil {
		return CaptureResult{}, err
	}
	// Queue first. If the process or network dies after this point, retry uses the
	// same event_id and the server's uniqueness constraint makes it idempotent.
	if err := queue.EnqueueBound(event, repo.Project); err != nil {
		return CaptureResult{}, err
	}
	result := CaptureResult{EventID: eventID, Queued: true}
	if transformedTruncated {
		result.Warning = "redaction expansion exceeded the one-MiB storage limit and was explicitly marked as truncated"
	}
	if !userConfig.enrolled() {
		userConfig, err = enrollProfile(repo, queue, userConfig)
		if err != nil {
			// The prompt is already durable. Enrollment and delivery retry on the
			// next prompt without blocking the AI tool.
			return result, nil
		}
	}
	client, err := NewAPIClient(userConfig.ServerURL, userConfig.Token, 500*time.Millisecond)
	if err != nil {
		return result, nil
	}
	client = client.WithEventIdentity(userConfig.UserID, userConfig.Email)
	flushed, _ := queue.Flush(client, maxAutomaticFlush)
	if flushed > 0 {
		remaining, countErr := queue.HasPending()
		result.Sent = countErr == nil && !remaining
		result.Queued = !result.Sent
	}
	return result, nil
}

func captureEventID(tool string, extracted ExtractedPrompt) (string, error) {
	if extracted.SourceEventKey == "" {
		return newUUID()
	}
	sum := sha256.Sum256([]byte("prompt-hook-v1\x00" + tool + "\x00" + extracted.SourceEventKey))
	return "hook-e-" + hex.EncodeToString(sum[:16]), nil
}

func claudeInvocationMatchesRepository(repoRoot string) bool {
	projectDir := strings.TrimSpace(os.Getenv("CLAUDE_PROJECT_DIR"))
	if projectDir == "" {
		return false
	}
	return sameCanonicalPath(projectDir, repoRoot)
}

func boundRedactedPrompt(value string) string {
	if len(value) <= maxQueuedPromptBytes {
		return value
	}
	limit := maxQueuedPromptBytes - len(redactionTruncationMarker)
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit] + redactionTruncationMarker
}

func Flush() (int, int, int, error) {
	workingDirectory, _ := os.Getwd()
	repo, repoErr := DiscoverRepository(workingDirectory)
	if repoErr == nil {
		repoErr = validateExternalConfigDirectory(repo.Root)
	}
	totalFlushed := 0
	totalRemaining := 0
	totalRejected := 0
	var problems []error
	processedTarget := false
	usedLegacy := false
	flushTarget := func(cfg UserConfig, queue *Queue) {
		processedTarget = true
		if _, err := queue.RetryRejected(); err != nil {
			problems = append(problems, err)
		}
		client, err := NewAPIClient(cfg.ServerURL, cfg.Token, 3*time.Second)
		if err != nil {
			problems = append(problems, err)
		} else {
			client = client.WithEventIdentity(cfg.UserID, cfg.Email)
			for {
				flushed, sendErr := queue.Flush(client, 0)
				totalFlushed += flushed
				if sendErr != nil {
					problems = append(problems, sendErr)
					var rejectedErr *rejectedEventsError
					if !errors.As(sendErr, &rejectedErr) {
						break
					}
				}
				pending, pendingErr := queue.HasPending()
				if pendingErr != nil {
					problems = append(problems, pendingErr)
					break
				}
				if !pending {
					break
				}
			}
		}
		remaining, countErr := queue.Count()
		if countErr != nil {
			problems = append(problems, countErr)
		} else {
			totalRemaining += remaining
		}
		rejected, rejectedErr := queue.RejectedCount()
		if rejectedErr != nil {
			problems = append(problems, rejectedErr)
		} else {
			totalRejected += rejected
		}
	}

	if repoErr == nil {
		profileCfg, profile, profileErr := loadUserConfigForProject(repo.Project)
		if profileErr == nil {
			queue, openErr := openQueueForProfile(profile)
			profileErr = openErr
			if profileErr != nil {
				problems = append(problems, profileErr)
			} else {
				usedLegacy = profile == ""
				if !profileCfg.enrolled() {
					profileCfg, profileErr = enrollProfile(repo, queue, profileCfg)
				}
				if profileErr != nil {
					remaining, countErr := queue.Count()
					if countErr != nil {
						problems = append(problems, countErr)
					} else {
						totalRemaining += remaining
					}
					rejected, rejectedErr := queue.RejectedCount()
					if rejectedErr != nil {
						problems = append(problems, rejectedErr)
					} else {
						totalRejected += rejected
					}
					problems = append(problems, profileErr)
					processedTarget = true
				} else {
					flushTarget(profileCfg, queue)
				}
			}
		} else if !errors.Is(profileErr, ErrNotConfigured) {
			problems = append(problems, profileErr)
		}
	}

	// Always drain the v0.1 global queue as a separate authenticated target.
	// This preserves upgrades without guessing which organization owned it.
	if !usedLegacy {
		legacyCfg, legacyErr := LoadUserConfig()
		if legacyErr == nil {
			legacyQueue, openErr := OpenQueue()
			if openErr != nil {
				problems = append(problems, openErr)
			} else {
				flushTarget(legacyCfg, legacyQueue)
			}
		} else if !errors.Is(legacyErr, ErrNotConfigured) {
			problems = append(problems, legacyErr)
		} else if !processedTarget {
			problems = append(problems, legacyErr)
		}
	}
	if !processedTarget && repoErr != nil {
		problems = append(problems, repoErr)
	}
	return totalFlushed, totalRemaining, totalRejected, errors.Join(problems...)
}
