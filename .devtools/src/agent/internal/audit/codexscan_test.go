package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

// setTestCloneAnchor pins the clone anchor so tests with fixed past timestamps
// are not filtered by the "only after clone" rule.
func setTestCloneAnchor(t *testing.T, repoRoot string, at time.Time) {
	t.Helper()
	dir := localStoreDir(repoRoot)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cloneAnchorFileName), []byte(at.UTC().Format(time.RFC3339Nano)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeCodexRollout(t *testing.T, codexHome, name string, lines []map[string]any) {
	t.Helper()
	dir := filepath.Join(codexHome, "sessions", "2026", "07", "21")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	for _, line := range lines {
		encoded, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		buffer.Write(encoded)
		buffer.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, name), buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeRawCodexFile(t *testing.T, path string, lines ...any) {
	t.Helper()
	var buffer bytes.Buffer
	for _, line := range lines {
		if raw, ok := line.(string); ok {
			buffer.WriteString(raw)
		} else {
			encoded, err := json.Marshal(line)
			if err != nil {
				t.Fatal(err)
			}
			buffer.Write(encoded)
		}
		buffer.WriteByte('\n')
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func meta(id, cwd string, extra map[string]any) map[string]any {
	payload := map[string]any{
		"id":            id,
		"cwd":           cwd,
		"cli_version":   "0.142.5",
		"source":        "cli",
		"thread_source": "user",
	}
	for key, value := range extra {
		payload[key] = value
	}
	return map[string]any{"type": "session_meta", "timestamp": "2026-07-21T00:00:00Z", "payload": payload}
}

func codexHookPayload(t *testing.T, transcriptPath, cwd, sessionID, prompt string, extra map[string]any) []byte {
	t.Helper()
	payload := map[string]any{
		"hook_event_name": "UserPromptSubmit",
		"prompt":          prompt,
		"session_id":      sessionID,
		"turn_id":         "turn-" + sessionID,
		"transcript_path": transcriptPath,
		"cwd":             cwd,
		"permission_mode": "default",
	}
	for key, value := range extra {
		payload[key] = value
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func userMsg(ts, text string) map[string]any {
	return map[string]any{"type": "event_msg", "timestamp": ts, "payload": map[string]any{"type": "user_message", "message": text}}
}

func assistantMsg(text string) map[string]any {
	return map[string]any{"type": "event_msg", "timestamp": "2026-07-21T00:00:05Z", "payload": map[string]any{"type": "agent_message", "message": text}}
}

func TestCodexScanCapturesOnlyThisRepoUserPromptsFromSessionLogs(t *testing.T) {
	const assistantSecret = "ASSISTANT-RESPONSE-MUST-NOT-BE-CAPTURED"
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex home with spaces")
	t.Setenv("CODEX_HOME", codexHome)

	// This repo's session: two user prompts and one assistant reply.
	writeCodexRollout(t, codexHome, "rollout-this.jsonl", []map[string]any{
		meta("sess-this", repository.Root, nil),
		userMsg("2026-07-21T00:00:01Z", "Escribe pruebas del carrito"),
		assistantMsg(assistantSecret),
		userMsg("2026-07-21T00:00:02Z", "Optimiza con password=zzz-secret-123"),
	})
	// A different project's session must never be captured here.
	writeCodexRollout(t, codexHome, "rollout-other.jsonl", []map[string]any{
		meta("sess-other", filepath.Join(t.TempDir(), "other-project"), nil),
		userMsg("2026-07-21T00:00:03Z", "prompt de otro proyecto"),
	})
	// A subagent session in this repo must be skipped.
	writeCodexRollout(t, codexHome, "rollout-subagent.jsonl", []map[string]any{
		meta("sess-sub", repository.Root, map[string]any{"agent_path": "some/agent"}),
		userMsg("2026-07-21T00:00:04Z", "prompt interno de subagente"),
	})
	// A user-shaped fork remains non-root and must also be skipped.
	writeCodexRollout(t, codexHome, "rollout-fork.jsonl", []map[string]any{
		meta("sess-fork", repository.Root, map[string]any{"forked_from_id": "sess-this"}),
		userMsg("2026-07-21T00:00:04Z", "prompt interno de sesion bifurcada"),
	})
	// Internal Codex sessions (for example memory consolidation) also emit
	// user_message-shaped records, but they are not employee prompts.
	writeCodexRollout(t, codexHome, "rollout-internal.jsonl", []map[string]any{
		meta("sess-internal", repository.Root, map[string]any{
			"source":        map[string]any{"internal": "memory_consolidation"},
			"thread_source": nil,
		}),
		userMsg("2026-07-21T00:00:05Z", "prompt interno de consolidacion"),
	})

	repo, err := DiscoverRepository(repository.Nested)
	if err != nil {
		t.Fatal(err)
	}
	added, err := scanAndStoreCodexPrompts(repo)
	if err != nil {
		t.Fatalf("scanAndStoreCodexPrompts() error = %v", err)
	}
	if added != 2 {
		t.Fatalf("captured %d prompts, want 2 (this repo's user prompts only)", added)
	}

	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("registry events = %d, want 2", len(events))
	}
	joined := ""
	for _, event := range events {
		if event.Tool != model.ToolCodex {
			t.Fatalf("tool = %q, want codex", event.Tool)
		}
		if event.SessionID != "sess-this" {
			t.Fatalf("session = %q, want sess-this", event.SessionID)
		}
		joined += event.Prompt + "\n"
	}
	if strings.Contains(joined, assistantSecret) {
		t.Fatal("assistant response leaked into the registry")
	}
	if strings.Contains(joined, "otro proyecto") {
		t.Fatal("another project's prompt leaked into the registry")
	}
	if strings.Contains(joined, "subagente") {
		t.Fatal("a subagent prompt leaked into the registry")
	}
	if strings.Contains(joined, "bifurcada") || strings.Contains(joined, "version antigua") {
		t.Fatal("a forked or pre-marker Codex prompt leaked into the registry")
	}
	if strings.Contains(joined, "consolidacion") {
		t.Fatal("an internal Codex prompt leaked into the registry")
	}
	if !strings.Contains(joined, "Escribe pruebas del carrito") {
		t.Fatal("expected user prompt missing")
	}
	if strings.Contains(joined, "zzz-secret-123") || !strings.Contains(joined, "[REDACTED]") {
		t.Fatal("secret in a scanned Codex prompt was not redacted")
	}

	// Re-scanning must not duplicate anything.
	again, err := scanAndStoreCodexPrompts(repo)
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Fatalf("re-scan captured %d prompts, want 0 (idempotent)", again)
	}
	events, _ = readRegistryEvents(repository.Root)
	if len(events) != 2 {
		t.Fatalf("registry after re-scan = %d events, want 2", len(events))
	}
}

func TestCodexScannerDoesNotDegradeThisProjectForUnrelatedCorruption(t *testing.T) {
	repoRoot := t.TempDir()
	otherRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "unrelated-corrupt.jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	encodedMeta, err := json.Marshal(meta("unrelated", otherRoot, nil))
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.Write(append(encodedMeta, '\n')); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.WriteString("{malformed}\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	prompts, scanErr := scanCodexFile(path, repoRoot)
	if scanErr != nil || len(prompts) != 0 {
		t.Fatalf("scanCodexFile() = %d prompts, %v; want unrelated corruption ignored", len(prompts), scanErr)
	}
}

func TestCodexScannerPoisonsUnscopedCorruptionWhenRolloutLaterMatchesRepo(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "unscoped-corrupt.jsonl")
	writeRawCodexFile(
		t,
		path,
		"{malformed}",
		meta("repo-session", repoRoot, nil),
		userMsg("2026-07-21T00:00:01Z", "must remain blocked"),
	)

	prompts, scanErr := scanCodexFile(path, repoRoot)
	if scanErr == nil || !strings.Contains(scanErr.Error(), "line 1") || len(prompts) != 0 {
		t.Fatalf("scanCodexFile() = %d prompts, %v; want poisoned repo rollout", len(prompts), scanErr)
	}

	writeRawCodexFile(
		t,
		path,
		meta("repo-session", repoRoot, nil),
		userMsg("2026-07-21T00:00:01Z", "captured after repair"),
	)
	prompts, scanErr = scanCodexFile(path, repoRoot)
	if scanErr != nil || len(prompts) != 1 || prompts[0].Prompt != "captured after repair" {
		t.Fatalf("scanCodexFile() after repair = %#v, %v; want one prompt", prompts, scanErr)
	}
}

func TestCodexScannerKeepsUnscopedCorruptionPendingAcrossForeignMetadata(t *testing.T) {
	repoRoot := t.TempDir()
	otherRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "pending-corrupt.jsonl")
	foreignLines := []any{
		"{malformed}",
		meta("other-session", otherRoot, nil),
		userMsg("2026-07-21T00:00:01Z", "foreign prompt"),
	}
	writeRawCodexFile(t, path, foreignLines...)

	prompts, scanErr := scanCodexFile(path, repoRoot)
	if scanErr != nil || len(prompts) != 0 {
		t.Fatalf("foreign-only scan = %d prompts, %v; want ignored corruption", len(prompts), scanErr)
	}

	writeRawCodexFile(
		t,
		path,
		append(
			foreignLines,
			meta("repo-session", repoRoot, nil),
			userMsg("2026-07-21T00:00:02Z", "must remain blocked"),
		)...,
	)
	prompts, scanErr = scanCodexFile(path, repoRoot)
	if scanErr == nil || !strings.Contains(scanErr.Error(), "line 1") || len(prompts) != 0 {
		t.Fatalf("foreign-to-repo scan = %d prompts, %v; want pending corruption materialized", len(prompts), scanErr)
	}
}

func TestCodexScannerScopesInvalidMetadataPayloadBeforeReportingIt(t *testing.T) {
	repoRoot := t.TempDir()
	otherRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "invalid-metadata.jsonl")
	foreignLines := []any{
		meta("other-session", otherRoot, nil),
		map[string]any{
			"type":      "session_meta",
			"timestamp": "2026-07-21T00:00:01Z",
			"payload":   "invalid",
		},
		userMsg("2026-07-21T00:00:02Z", "foreign prompt"),
	}
	writeRawCodexFile(t, path, foreignLines...)

	prompts, scanErr := scanCodexFile(path, repoRoot)
	if scanErr != nil || len(prompts) != 0 {
		t.Fatalf("foreign invalid metadata = %d prompts, %v; want no project warning", len(prompts), scanErr)
	}

	writeRawCodexFile(
		t,
		path,
		append(
			foreignLines,
			meta("repo-session", repoRoot, nil),
			userMsg("2026-07-21T00:00:03Z", "must remain blocked"),
		)...,
	)
	prompts, scanErr = scanCodexFile(path, repoRoot)
	if scanErr == nil || !strings.Contains(scanErr.Error(), "line 2") || len(prompts) != 0 {
		t.Fatalf("invalid metadata before repo scope = %d prompts, %v; want poisoned rollout", len(prompts), scanErr)
	}
}

func TestCodexScannerUpdatesSessionIDOnRepositoryTransition(t *testing.T) {
	repoRoot := t.TempDir()
	otherRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "session-transition.jsonl")
	writeRawCodexFile(
		t,
		path,
		meta("other-session", otherRoot, nil),
		userMsg("2026-07-21T00:00:01Z", "foreign prompt"),
		meta("repo-session", repoRoot, nil),
		userMsg("2026-07-21T00:00:02Z", "repo prompt"),
	)

	prompts, scanErr := scanCodexFile(path, repoRoot)
	if scanErr != nil || len(prompts) != 1 {
		t.Fatalf("scanCodexFile() = %#v, %v; want one repo prompt", prompts, scanErr)
	}
	if prompts[0].SessionID != "repo-session" || prompts[0].Position != 4 || prompts[0].Prompt != "repo prompt" {
		t.Fatalf("transition prompt = %#v; want current session id, position, and prompt", prompts[0])
	}
}

func TestCodexScannerDiscardsPromptsWhenLateMetadataRevealsSubagent(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "late-subagent.jsonl")
	writeRawCodexFile(
		t,
		path,
		meta("parent-session", repoRoot, nil),
		userMsg("2026-07-21T00:00:01Z", "internal prompt before provenance marker"),
		meta("fork-session", repoRoot, map[string]any{"forked_from_id": "parent-session"}),
		userMsg("2026-07-21T00:00:02Z", "internal prompt after provenance marker"),
	)

	prompts, scanErr := scanCodexFile(path, repoRoot)
	if scanErr != nil || len(prompts) != 0 {
		t.Fatalf("late subagent marker = %#v, %v; want entire rollout discarded", prompts, scanErr)
	}
}

func TestCodexScannerDoesNotLetAmbiguousForeignMetadataPoisonRepoTransition(t *testing.T) {
	repoRoot := t.TempDir()
	otherRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "foreign-legacy.jsonl")
	writeRawCodexFile(
		t,
		path,
		meta("legacy-foreign", otherRoot, map[string]any{"cli_version": "0.100.0", "source": "future-source"}),
		userMsg("2026-07-21T00:00:01Z", "foreign prompt"),
		meta("repo-session", repoRoot, nil),
		userMsg("2026-07-21T00:00:02Z", "repo prompt"),
	)

	prompts, scanErr := scanCodexFile(path, repoRoot)
	if scanErr != nil || len(prompts) != 1 || prompts[0].SessionID != "repo-session" || prompts[0].Prompt != "repo prompt" {
		t.Fatalf("foreign legacy transition = %#v, %v; want current repo prompt", prompts, scanErr)
	}
}

func TestCodexScannerReportsAmbiguousMetadataForThisRepository(t *testing.T) {
	repoRoot := t.TempDir()
	for _, testCase := range []struct {
		name  string
		extra map[string]any
	}{
		{
			name:  "legacy version",
			extra: map[string]any{"cli_version": "0.100.0"},
		},
		{
			name:  "future source",
			extra: map[string]any{"source": "future-source"},
		},
		{
			name:  "non-string source",
			extra: map[string]any{"source": 42},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ambiguous.jsonl")
			writeRawCodexFile(
				t,
				path,
				meta("repo-session", repoRoot, testCase.extra),
				userMsg("2026-07-21T00:00:01Z", "must remain blocked"),
			)

			prompts, scanErr := scanCodexFile(path, repoRoot)
			if scanErr == nil || len(prompts) != 0 {
				t.Fatalf("ambiguous repo metadata = %#v, %v; want unhealthy blocked rollout", prompts, scanErr)
			}
		})
	}
}

func TestCodexScannerAcceptsOnlySafePrereleaseVersionsPastRecoveryFloor(t *testing.T) {
	repoRoot := t.TempDir()
	for _, testCase := range []struct {
		name    string
		version string
		want    bool
	}{
		{name: "real alpha 145", version: "0.145.0-alpha.18", want: true},
		{name: "real alpha 146", version: "0.146.0-alpha.3", want: true},
		{name: "floor release candidate", version: "0.134.0-rc.1", want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "prerelease.jsonl")
			writeRawCodexFile(
				t,
				path,
				meta("repo-session", repoRoot, map[string]any{
					"cli_version": testCase.version,
					"source":      "vscode",
				}),
				userMsg("2026-07-21T00:00:01Z", "root user recovery fixture"),
			)

			prompts, scanErr := scanCodexFile(path, repoRoot)
			if testCase.want {
				if scanErr != nil ||
					len(prompts) != 1 ||
					prompts[0].Prompt != "root user recovery fixture" {
					t.Fatalf(
						"scanCodexFile() for %q = %#v, %v; want one root user prompt",
						testCase.version,
						prompts,
						scanErr,
					)
				}
				return
			}
			if scanErr == nil || len(prompts) != 0 {
				t.Fatalf(
					"scanCodexFile() for %q = %#v, %v; want unsupported metadata",
					testCase.version,
					prompts,
					scanErr,
				)
			}
		})
	}
}

func TestCodexScannerRejectsIncompleteMetadataWhenRolloutMatchesRepo(t *testing.T) {
	repoRoot := t.TempDir()
	cases := []struct {
		name    string
		payload any
	}{
		{name: "null", payload: nil},
		{name: "empty object", payload: map[string]any{}},
		{
			name: "empty id",
			payload: map[string]any{
				"id":            "",
				"cwd":           repoRoot,
				"cli_version":   "0.142.5",
				"source":        "cli",
				"thread_source": "user",
			},
		},
		{
			name: "whitespace id",
			payload: map[string]any{
				"id":            "   ",
				"cwd":           repoRoot,
				"cli_version":   "0.142.5",
				"source":        "cli",
				"thread_source": "user",
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "incomplete.jsonl")
			writeRawCodexFile(
				t,
				path,
				map[string]any{
					"type":      "session_meta",
					"timestamp": "2026-07-21T00:00:00Z",
					"payload":   testCase.payload,
				},
				meta("repo-session", repoRoot, nil),
				userMsg("2026-07-21T00:00:01Z", "must remain blocked"),
			)

			prompts, scanErr := scanCodexFile(path, repoRoot)
			if scanErr == nil || len(prompts) != 0 {
				t.Fatalf("incomplete metadata = %#v, %v; want poisoned rollout", prompts, scanErr)
			}
		})
	}
}

func TestCodexScannerRejectsNullMetadataAfterRepositoryScope(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "null-after-scope.jsonl")
	writeRawCodexFile(
		t,
		path,
		meta("repo-session", repoRoot, nil),
		map[string]any{
			"type":      "session_meta",
			"timestamp": "2026-07-21T00:00:01Z",
			"payload":   nil,
		},
		userMsg("2026-07-21T00:00:02Z", "must remain blocked"),
	)

	prompts, scanErr := scanCodexFile(path, repoRoot)
	if scanErr == nil || len(prompts) != 0 {
		t.Fatalf("null metadata after repo scope = %#v, %v; want unhealthy blocked rollout", prompts, scanErr)
	}
}

func TestCodexScannerReportsMalformedUserEventPayloadsInRepositoryScope(t *testing.T) {
	repoRoot := t.TempDir()
	for _, testCase := range []struct {
		name    string
		payload any
	}{
		{name: "null", payload: nil},
		{name: "empty object", payload: map[string]any{}},
		{name: "missing message", payload: map[string]any{"type": "user_message"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad-event.jsonl")
			writeRawCodexFile(
				t,
				path,
				meta("repo-session", repoRoot, nil),
				map[string]any{
					"type":      "event_msg",
					"timestamp": "2026-07-21T00:00:01Z",
					"payload":   testCase.payload,
				},
			)

			prompts, scanErr := scanCodexFile(path, repoRoot)
			if scanErr == nil || len(prompts) != 0 {
				t.Fatalf("malformed user event = %#v, %v; want explicit health error", prompts, scanErr)
			}
		})
	}
}

func TestCodexScannerPoisonsMissingRecordTypeAfterRepositoryScope(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "missing-type.jsonl")
	writeRawCodexFile(
		t,
		path,
		meta("repo-session", repoRoot, nil),
		map[string]any{},
		userMsg("2026-07-21T00:00:01Z", "must remain blocked"),
	)

	prompts, scanErr := scanCodexFile(path, repoRoot)
	if scanErr == nil || len(prompts) != 0 {
		t.Fatalf("missing record type = %#v, %v; want poisoned rollout", prompts, scanErr)
	}

	writeRawCodexFile(
		t,
		path,
		meta("repo-session", repoRoot, nil),
		userMsg("2026-07-21T00:00:01Z", "captured after repair"),
	)
	prompts, scanErr = scanCodexFile(path, repoRoot)
	if scanErr != nil || len(prompts) != 1 || prompts[0].Prompt != "captured after repair" {
		t.Fatalf("missing-type repair = %#v, %v; want recovered prompt", prompts, scanErr)
	}
}

func TestCodexScannerScopesOversizedLinesToThisRepository(t *testing.T) {
	repoRoot := t.TempDir()
	otherRoot := t.TempDir()
	for _, testCase := range []struct {
		name      string
		cwd       string
		wantError bool
	}{
		{name: "foreign", cwd: otherRoot, wantError: false},
		{name: "this repository", cwd: repoRoot, wantError: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "oversized.jsonl")
			writeRawCodexFile(
				t,
				path,
				meta("session", testCase.cwd, nil),
				strings.Repeat("x", 2048),
			)

			prompts, scanErr := scanCodexFileWithLineLimit(path, repoRoot, 1024)
			if len(prompts) != 0 || (scanErr != nil) != testCase.wantError {
				t.Fatalf("scanner error scope = %d prompts, %v; wantError=%v", len(prompts), scanErr, testCase.wantError)
			}
		})
	}
}

func TestCodexScannerContinuesAfterForeignOversizedLineAndPoisonsRepoTransition(t *testing.T) {
	repoRoot := t.TempDir()
	otherRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "oversized-transition.jsonl")
	writeRawCodexFile(
		t,
		path,
		meta("other-session", otherRoot, nil),
		strings.Repeat("x", 2048),
		meta("repo-session", repoRoot, nil),
		userMsg("2026-07-21T00:00:01Z", "must remain blocked"),
	)

	prompts, scanErr := scanCodexFileWithLineLimit(path, repoRoot, 1024)
	if scanErr == nil || len(prompts) != 0 || !strings.Contains(scanErr.Error(), "line 2") {
		t.Fatalf("oversized foreign-to-repo transition = %#v, %v; want pending corruption materialized", prompts, scanErr)
	}
}

func TestCodexScannerBoundsMaterializedDiagnostics(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "many-errors.jsonl")
	lines := []any{meta("repo-session", repoRoot, nil)}
	for i := 0; i < maxCollectedProblems+5; i++ {
		lines = append(lines, map[string]any{
			"type":      "event_msg",
			"timestamp": "2026-07-21T00:00:01Z",
			"payload":   "invalid",
		})
	}
	writeRawCodexFile(t, path, lines...)

	prompts, scanErr := scanCodexFile(path, repoRoot)
	if scanErr == nil || len(prompts) != 0 || !strings.Contains(scanErr.Error(), "additional problems suppressed") {
		t.Fatalf("bounded diagnostics = %d prompts, %v; want capped error summary", len(prompts), scanErr)
	}
}

func TestCodexFilePagingContinuesAtFirstUnbufferedPrompt(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "paged.jsonl")
	lines := []any{meta("paged-session", repoRoot, nil)}
	for index := 0; index < 5; index++ {
		lines = append(
			lines,
			userMsg(
				time.Date(2026, 7, 21, 0, 0, index+1, 0, time.UTC).Format(time.RFC3339),
				fmt.Sprintf("prompt-%d", index+1),
			),
		)
	}
	writeRawCodexFile(t, path, lines...)

	startLine := 1
	var positions []int
	for page := 0; page < 3; page++ {
		prompts, nextLine, scanErr := scanCodexFilePage(
			path,
			repoRoot,
			maxProviderTranscriptLineBytes,
			startLine,
			newRecoveredPromptCollectorWithLimits(2, 1024, 512),
		)
		if scanErr != nil {
			t.Fatal(scanErr)
		}
		for _, prompt := range prompts {
			positions = append(positions, prompt.Position)
		}
		if page < 2 {
			if nextLine == 0 {
				t.Fatalf("page %d completed early", page+1)
			}
			startLine = nextLine
		} else if nextLine != 0 {
			t.Fatalf("final page nextLine = %d; want complete", nextLine)
		}
	}
	if fmt.Sprint(positions) != "[2 3 4 5 6]" {
		t.Fatalf("paged positions = %v; want every prompt exactly once", positions)
	}
}

func TestCodexCursorConsumesDirectCorrelationBehindResumeLine(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "cursor-direct-correlation.jsonl")
	timestamp := time.Date(2026, 7, 21, 0, 0, 1, 0, time.UTC)
	writeRawCodexFile(
		t,
		path,
		meta("cursor-direct-session", repoRoot, nil),
		userMsg(timestamp.Format(time.RFC3339), "same prompt"),
		userMsg(timestamp.Format(time.RFC3339), "same prompt"),
	)

	existing := model.Event{
		EventID:   "hook-e-direct",
		Timestamp: timestamp,
		Tool:      model.ToolCodex,
		SessionID: "cursor-direct-session",
		Prompt:    "same prompt",
	}
	build := func(prompt scannedPrompt) model.Event {
		return model.Event{
			EventID:   fmt.Sprintf("codex-h-%d", prompt.Position),
			Timestamp: prompt.Timestamp,
			Tool:      model.ToolCodex,
			SessionID: prompt.SessionID,
			Prompt:    prompt.Prompt,
		}
	}
	deduper := newRecoveredPromptDeduper([]model.Event{existing}, build, nil)
	prompts, nextLine, _, scanErr := scanCodexFilePageSnapshot(
		path,
		repoRoot,
		maxProviderTranscriptLineBytes,
		3,
		newRecoveredPromptCollectorWithLimits(2, 1024, 512),
		deduper.Skip,
		nil,
	)
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	if nextLine != 0 || len(prompts) != 1 || prompts[0].Position != 3 {
		t.Fatalf(
			"resumed cursor = %#v, next %d; want the later distinct prompt on line 3",
			prompts,
			nextLine,
		)
	}
}

func TestCodexScanCursorPersistsAndEventuallyCompletesLargeFile(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	lines := []map[string]any{meta("cursor-session", repository.Root, nil)}
	for index := 0; index < 5; index++ {
		lines = append(
			lines,
			userMsg(
				time.Date(2026, 7, 21, 0, 0, index+1, 0, time.UTC).Format(time.RFC3339),
				fmt.Sprintf("cursor-prompt-%d", index+1),
			),
		)
	}
	writeCodexRollout(t, codexHome, "cursor.jsonl", lines)
	rolloutPath := filepath.Join(codexHome, "sessions", "2026", "07", "21", "cursor.jsonl")

	state := providerScanState{
		Version:            currentProviderScanStateVersion,
		AuthoritativeFiles: map[string]authoritativeFingerprint{},
		Files:              map[string]scanFingerprint{},
		Cursors:            map[string]scanCursor{},
	}
	factory := func() *recoveredPromptCollector {
		return newRecoveredPromptCollectorWithLimits(2, 1024, 512)
	}
	var positions []int
	for page := 0; page < 3; page++ {
		if err := invalidateScanStateIfStoreSetChanged(repository.Root, &state); err != nil {
			t.Fatal(err)
		}
		prompts, pending, scanErr := scanCodexPromptsWithCollectorFactory(
			repository.Root,
			&state,
			factory,
		)
		if scanErr != nil {
			t.Fatal(scanErr)
		}
		if pending != (page < 2) {
			t.Fatalf("page %d pending = %v", page+1, pending)
		}
		for _, prompt := range prompts {
			positions = append(positions, prompt.Position)
		}
		if err := updateScanStateStoreSet(repository.Root, &state); err != nil {
			t.Fatal(err)
		}
		if err := saveProviderScanState(repository.Root, model.ToolCodex, state); err != nil {
			t.Fatal(err)
		}
		var err error
		state, err = loadProviderScanState(repository.Root, model.ToolCodex)
		if err != nil {
			t.Fatal(err)
		}
		if page == 0 {
			file, err := os.OpenFile(rolloutPath, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			appended, err := json.Marshal(
				userMsg("2026-07-21T00:00:06Z", "cursor-prompt-6"),
			)
			if err == nil {
				_, err = file.Write(append(appended, '\n'))
			}
			closeErr := file.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
		}
	}
	if fmt.Sprint(positions) != "[2 3 4 5 6 7]" {
		t.Fatalf("durable cursor positions = %v; want every prompt exactly once", positions)
	}
	if len(state.Cursors) != 0 || len(state.Files) != 1 {
		t.Fatalf("completed cursor state = %#v; want one completed fingerprint", state)
	}
}

func TestCodexPagedRecoveryStoresEveryPromptAcrossInvocations(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	lines := []map[string]any{meta("paged-store-session", repository.Root, nil)}
	for index := 0; index < 5; index++ {
		lines = append(
			lines,
			userMsg(
				time.Date(2026, 7, 21, 0, 0, index+1, 0, time.UTC).Format(time.RFC3339),
				fmt.Sprintf("paged-store-prompt-%d", index+1),
			),
		)
	}
	writeCodexRollout(t, codexHome, "paged-store.jsonl", lines)
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	factory := func() *recoveredPromptCollector {
		return newRecoveredPromptCollectorWithLimits(2, 1024, 512)
	}

	for index, wantAdded := range []int{2, 2, 1, 0} {
		added, scanErr := scanAndStoreCodexPromptsWithCollectorFactory(repo, factory)
		wantPending := index < 2
		if added != wantAdded || errors.Is(scanErr, errProviderRecoveryPending) != wantPending {
			t.Fatalf(
				"recovery pass %d = added %d, err %v; want added %d, pending %v",
				index+1,
				added,
				scanErr,
				wantAdded,
				wantPending,
			)
		}
		if scanErr != nil && !wantPending {
			t.Fatalf("recovery pass %d unexpected error: %v", index+1, scanErr)
		}
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Fatalf("paged recovery stored %d prompts, want 5", len(events))
	}
	counts := make(map[string]int)
	for _, event := range events {
		counts[event.Prompt]++
	}
	for index := 0; index < 5; index++ {
		prompt := fmt.Sprintf("paged-store-prompt-%d", index+1)
		if counts[prompt] != 1 {
			t.Fatalf("prompt %q stored %d times", prompt, counts[prompt])
		}
	}
}

func TestCodexRecoveryErrorDoesNotStarveLaterBoundedBatches(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	lines := []map[string]any{
		meta("error-pages-session", repository.Root, nil),
		{
			"type":      "event_msg",
			"timestamp": "2026-07-21T00:00:00Z",
			"payload":   "invalid-user-event",
		},
	}
	for index := 0; index < 5; index++ {
		lines = append(
			lines,
			userMsg(
				time.Date(2026, 7, 21, 0, 0, index+1, 0, time.UTC).Format(time.RFC3339),
				fmt.Sprintf("error-page-prompt-%d", index+1),
			),
		)
	}
	writeCodexRollout(t, codexHome, "error-pages.jsonl", lines)
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	factory := func() *recoveredPromptCollector {
		return newRecoveredPromptCollectorWithLimits(2, 1024, 512)
	}

	for pass, wantAdded := range []int{2, 2, 1, 0} {
		added, scanErr := scanAndStoreCodexPromptsWithCollectorFactory(repo, factory)
		if scanErr == nil {
			t.Fatalf("recovery pass %d omitted the persistent transcript diagnostic", pass+1)
		}
		if added != wantAdded {
			t.Fatalf(
				"recovery pass %d added %d prompts, want %d (error: %v)",
				pass+1,
				added,
				wantAdded,
				scanErr,
			)
		}
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Fatalf("error-paged recovery stored %d prompts, want 5", len(events))
	}
	for index, event := range events {
		want := fmt.Sprintf("error-page-prompt-%d", index+1)
		if event.Prompt != want {
			t.Fatalf("error-paged event %d = %q, want %q", index+1, event.Prompt, want)
		}
	}
}

func TestCodexRecoveryReservesExactHistoryOutsideBoundedBatch(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	timestamp := time.Date(2026, 7, 21, 0, 0, 1, 0, time.UTC)
	const (
		sessionID = "exact-outside-batch-session"
		prompt    = "same timestamp and prompt"
	)
	writeCodexRollout(t, codexHome, "exact-outside-batch.jsonl", []map[string]any{
		meta(sessionID, repository.Root, nil),
		{
			"type":      "event_msg",
			"timestamp": "2026-07-21T00:00:00Z",
			"payload":   "persistent-invalid-user-event",
		},
		userMsg(timestamp.Format(time.RFC3339), prompt),
		userMsg(timestamp.Format(time.RFC3339), prompt),
	})
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	_, email, _ := automaticIdentity(repo.Root)
	exactSecond := sampleEvent(codexHistoryEventID(sessionID, 4, timestamp), prompt)
	exactSecond.Timestamp = timestamp
	exactSecond.UserID = localUserID(email)
	exactSecond.UserEmail = email
	exactSecond.Tool = model.ToolCodex
	exactSecond.RepositoryName = repo.Name
	exactSecond.RepositoryRemote = repo.Remote
	exactSecond.Branch = repo.Branch
	exactSecond.CommitHash = repo.CommitHash
	exactSecond.SessionID = sessionID
	if err := writeLocalEvent(repo.Root, exactSecond); err != nil {
		t.Fatal(err)
	}
	factory := func() *recoveredPromptCollector {
		return newRecoveredPromptCollectorWithLimits(1, 1024, 512)
	}

	added, scanErr := scanAndStoreCodexPromptsWithCollectorFactory(repo, factory)
	if scanErr == nil {
		t.Fatal("recovery omitted the persistent transcript diagnostic")
	}
	if added != 1 {
		t.Fatalf(
			"recovery added %d prompts, want the distinct first row (error: %v)",
			added,
			scanErr,
		)
	}
	events, err := readAllAuthoritativeEvents(repo.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("exact reservation retained %d prompts, want 2", len(events))
	}
}

func TestCodexRecoveryRepairsAliasWhenTargetBecomesExact(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	timestamp := time.Date(2026, 7, 21, 0, 0, 1, 0, time.UTC)
	const (
		sessionID = "alias-target-exact-session"
		prompt    = "same prompt for repaired alias"
	)
	writeCodexRollout(t, codexHome, "alias-target-exact.jsonl", []map[string]any{
		meta(sessionID, repository.Root, nil),
		userMsg(timestamp.Format(time.RFC3339), prompt),
		userMsg(timestamp.Format(time.RFC3339), prompt),
	})
	rolloutPath := filepath.Join(
		codexHome,
		"sessions",
		"2026",
		"07",
		"21",
		"alias-target-exact.jsonl",
	)
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	_, email, _ := automaticIdentity(repo.Root)
	firstID := codexHistoryEventID(sessionID, 2, timestamp)
	secondID := codexHistoryEventID(sessionID, 3, timestamp)
	exactSecond := sampleEvent(secondID, prompt)
	exactSecond.Timestamp = timestamp
	exactSecond.UserID = localUserID(email)
	exactSecond.UserEmail = email
	exactSecond.Tool = model.ToolCodex
	exactSecond.RepositoryName = repo.Name
	exactSecond.RepositoryRemote = repo.Remote
	exactSecond.Branch = repo.Branch
	exactSecond.CommitHash = repo.CommitHash
	exactSecond.SessionID = sessionID
	if err := writeLocalEvent(repo.Root, exactSecond); err != nil {
		t.Fatal(err)
	}
	storeSet, err := authoritativeFileState(repo.Root)
	if err != nil {
		t.Fatal(err)
	}
	state := emptyProviderScanState()
	state.AuthoritativeFiles = storeSet
	state.HistoryAliases[firstID] = secondID
	if err := updateScanState(
		&state,
		model.ToolCodex,
		rolloutPath,
		mustFileIdentity(t, rolloutPath),
	); err != nil {
		t.Fatal(err)
	}
	if err := saveProviderScanState(repo.Root, model.ToolCodex, state); err != nil {
		t.Fatal(err)
	}
	factory := func() *recoveredPromptCollector {
		return newRecoveredPromptCollectorWithLimits(1, 1024, 512)
	}
	added, scanErr := scanAndStoreCodexPromptsWithCollectorFactory(repo, factory)
	if added != 1 || scanErr != nil {
		t.Fatalf("alias repair = added %d, err %v; want first prompt restored", added, scanErr)
	}
	events, err := readAllAuthoritativeEvents(repo.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("alias repair retained %d prompts, want 2", len(events))
	}
}

func TestCodexPagedLegacyAliasesPreserveLaterPrompt(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	const sessionID = "legacy-alias-session"
	lines := []map[string]any{meta(sessionID, repository.Root, nil)}
	for index := 0; index < 3; index++ {
		lines = append(
			lines,
			userMsg(
				time.Date(2026, 7, 21, 0, 0, index+1, 0, time.UTC).Format(time.RFC3339),
				fmt.Sprintf("legacy-prompt-%d", index+1),
			),
		)
	}
	writeCodexRollout(t, codexHome, "legacy-alias.jsonl", lines)
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	_, email, _ := automaticIdentity(repo.Root)
	for index := 0; index < 3; index++ {
		event := sampleEvent(
			fmt.Sprintf("codex-h-legacy-%d", index+1),
			fmt.Sprintf("legacy-prompt-%d", index+1),
		)
		event.Timestamp = time.Date(2026, 7, 21, 0, 0, index+1, 0, time.UTC)
		event.UserID = localUserID(email)
		event.UserEmail = email
		event.Tool = model.ToolCodex
		event.RepositoryName = repo.Name
		event.RepositoryRemote = repo.Remote
		event.Branch = repo.Branch
		event.CommitHash = repo.CommitHash
		event.SessionID = sessionID
		if err := writeLocalEvent(repo.Root, event); err != nil {
			t.Fatal(err)
		}
	}
	factory := func() *recoveredPromptCollector {
		return newRecoveredPromptCollectorWithLimits(2, 1024, 512)
	}
	added, scanErr := scanAndStoreCodexPromptsWithCollectorFactory(repo, factory)
	if added != 0 || !errors.Is(scanErr, errProviderRecoveryPending) {
		t.Fatalf("legacy page 1 = added %d, err %v; want 0 and pending", added, scanErr)
	}
	added, scanErr = scanAndStoreCodexPromptsWithCollectorFactory(repo, factory)
	if added != 0 || scanErr != nil {
		t.Fatalf("legacy page 2 = added %d, err %v; want 0, nil", added, scanErr)
	}

	rolloutPath := filepath.Join(
		codexHome,
		"sessions",
		"2026",
		"07",
		"21",
		"legacy-alias.jsonl",
	)
	file, err := os.OpenFile(rolloutPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(userMsg("2026-07-21T00:00:04Z", "fresh-after-legacy"))
	if err == nil {
		_, err = file.Write(append(encoded, '\n'))
	}
	closeErr := file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	added, scanErr = scanAndStoreCodexPromptsWithCollectorFactory(repo, factory)
	if added != 1 || scanErr != nil {
		t.Fatalf("legacy growth = added %d, err %v; want fresh prompt", added, scanErr)
	}
	events, err := readAllAuthoritativeEvents(repo.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("legacy alias recovery retained %d prompts, want 4", len(events))
	}
	foundFresh := false
	for _, event := range events {
		if event.Prompt == "fresh-after-legacy" {
			foundFresh = true
		}
	}
	if !foundFresh {
		t.Fatal("legacy alias recovery omitted the later fresh prompt")
	}
}

func TestCodexRecoverySkipsPreClonePromptsBeforeBatchBudget(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	anchor := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	setTestCloneAnchor(t, repository.Root, anchor)
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	lines := []map[string]any{
		meta("pre-clone-budget-session", repository.Root, nil),
		{
			"type":      "event_msg",
			"timestamp": "2026-07-21T12:00:00Z",
			"payload":   "invalid-user-event",
		},
	}
	for index := 0; index < 5; index++ {
		lines = append(
			lines,
			userMsg(
				anchor.Add(-time.Duration(index+1)*time.Hour).Format(time.RFC3339),
				fmt.Sprintf("pre-clone-prompt-%d", index+1),
			),
		)
	}
	for index := 0; index < 3; index++ {
		lines = append(
			lines,
			userMsg(
				anchor.Add(time.Duration(index+1)*time.Hour).Format(time.RFC3339),
				fmt.Sprintf("post-clone-prompt-%d", index+1),
			),
		)
	}
	writeCodexRollout(t, codexHome, "pre-clone-budget.jsonl", lines)
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	factory := func() *recoveredPromptCollector {
		return newRecoveredPromptCollectorWithLimits(2, 1024, 512)
	}
	for pass, wantAdded := range []int{2, 1, 0} {
		added, scanErr := scanAndStoreCodexPromptsWithCollectorFactory(repo, factory)
		if scanErr == nil {
			t.Fatalf("recovery pass %d omitted persistent diagnostic", pass+1)
		}
		if added != wantAdded {
			t.Fatalf("recovery pass %d added %d, want %d", pass+1, added, wantAdded)
		}
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("pre-clone budget recovery stored %d prompts, want 3", len(events))
	}
	for _, event := range events {
		if !strings.HasPrefix(event.Prompt, "post-clone-prompt-") {
			t.Fatalf("pre-clone prompt consumed/stored by recovery: %q", event.Prompt)
		}
	}
}

func TestCodexDirectCaptureUsesDocumentedRootHookEnvelope(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)

	writeCodexRollout(t, codexHome, "root.jsonl", []map[string]any{
		meta("root-session", repository.Root, nil),
	})
	rootTranscript := filepath.Join(codexHome, "sessions", "2026", "07", "21", "root.jsonl")
	result, err := Capture(model.ToolCodex, bytes.NewReader(codexHookPayload(
		t,
		rootTranscript,
		repository.Nested,
		"root-session",
		"prompt humano directo",
		nil,
	)))
	if err != nil {
		t.Fatalf("root Capture() error = %v", err)
	}
	if !result.Sent {
		t.Fatalf("root Capture() result = %#v, want durable local capture", result)
	}

	// Current Codex emits these markers inside thread-spawned subagents. Even a
	// forged parent transcript cannot make such an input eligible.
	_, err = Capture(model.ToolCodex, bytes.NewReader(codexHookPayload(
		t,
		rootTranscript,
		repository.Nested,
		"root-session",
		"prompt interno marcado",
		map[string]any{"agent_id": "child-session", "agent_type": "explorer"},
	)))
	if !errors.Is(err, ErrNotUserPrompt) {
		t.Fatalf("marked subagent Capture() error = %v, want ErrNotUserPrompt", err)
	}

	for _, missing := range []string{"session_id", "turn_id", "cwd", "permission_mode"} {
		payload := map[string]any{
			"hook_event_name": "UserPromptSubmit",
			"prompt":          "prompt con sobre incompleto",
			"session_id":      "missing-session",
			"turn_id":         "turn-missing",
			"cwd":             repository.Nested,
			"permission_mode": "default",
		}
		delete(payload, missing)
		encoded, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, captureErr := Capture(model.ToolCodex, bytes.NewReader(encoded)); captureErr == nil ||
			errors.Is(captureErr, ErrNotUserPrompt) {
			t.Fatalf("missing %s Capture() error = %v, want blocking envelope error", missing, captureErr)
		}
	}

	events, err := readAllAuthoritativeEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Prompt != "prompt humano directo" {
		t.Fatalf("direct Codex events = %#v, want only the verified root prompt", events)
	}
}

func TestCodexScanRebuildsDeletedAuthoritativeStoreDespiteCachedState(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	writeCodexRollout(t, codexHome, "rebuild.jsonl", []map[string]any{
		meta("rebuild-session", repository.Root, nil),
		userMsg("2026-07-21T00:00:01Z", "first recoverable prompt"),
		userMsg("2026-07-21T00:00:02Z", "second recoverable prompt"),
	})
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if added, err := scanAndStoreCodexPrompts(repo); err != nil || added != 2 {
		t.Fatalf("initial scan = %d, %v; want 2, nil", added, err)
	}
	for _, directory := range []string{localStoreDir(repository.Root), registryDir(repository.Root)} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), registryFileExt) {
				if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
					t.Fatal(err)
				}
			}
		}
	}

	added, err := scanAndStoreCodexPrompts(repo)
	if err != nil || added != 2 {
		t.Fatalf("recovery scan = %d, %v; want 2 restored prompts", added, err)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil || len(events) != 2 {
		t.Fatalf("restored registry = %d events, %v; want 2", len(events), err)
	}
}

func TestCodexScanRebuildsHistoryWhenAuthoritativeFileIsRecreatedWithSameName(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	writeCodexRollout(t, codexHome, "same-name.jsonl", []map[string]any{
		meta("same-name-session", repository.Root, nil),
		userMsg("2026-07-21T00:00:01Z", "recoverable prompt one"),
		userMsg("2026-07-21T00:00:02Z", "recoverable prompt two"),
	})
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if added, err := scanAndStoreCodexPrompts(repo); err != nil || added != 2 {
		t.Fatalf("initial scan = %d, %v; want 2, nil", added, err)
	}
	entries, err := os.ReadDir(localStoreDir(repository.Root))
	if err != nil {
		t.Fatal(err)
	}
	var backupPath, userID string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), registryFileExt) {
			backupPath = filepath.Join(localStoreDir(repository.Root), entry.Name())
			userID = strings.TrimSuffix(entry.Name(), registryFileExt)
			break
		}
	}
	if backupPath == "" {
		t.Fatal("initial scan created no authoritative backup")
	}
	if err := os.Remove(backupPath); err != nil {
		t.Fatal(err)
	}
	replacement := sampleEvent("hook-e-replacement", "new direct prompt after store recreation")
	replacement.UserID = userID
	replacement.UserEmail = "tests@example.invalid"
	replacement.Tool = model.ToolCodex
	replacement.RepositoryName = repo.Name
	replacement.RepositoryRemote = repo.Remote
	replacement.SessionID = "direct-session"
	if err := writeLocalEvent(repository.Root, replacement); err != nil {
		t.Fatal(err)
	}

	added, err := scanAndStoreCodexPrompts(repo)
	if err != nil || added != 2 {
		t.Fatalf("same-name recovery scan = %d, %v; want 2 restored prompts", added, err)
	}
	events, err := readEventsFile(backupPath)
	if err != nil || len(events) != 3 {
		t.Fatalf("same-name authoritative recovery = %d events, %v; want direct plus 2 restored", len(events), err)
	}
}

func TestCodexScanQuarantinesInvalidCacheAndRegeneratesIt(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	writeCodexRollout(t, codexHome, "cache.jsonl", []map[string]any{
		meta("cache-session", repository.Root, nil),
		userMsg("2026-07-21T00:00:01Z", "cache recovery prompt"),
	})
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanAndStoreCodexPrompts(repo); err != nil {
		t.Fatal(err)
	}
	statePath := scanStatePath(repository.Root, model.ToolCodex)
	if err := os.WriteFile(statePath, []byte(`{"version":`), 0o600); err != nil {
		t.Fatal(err)
	}

	if added, err := scanAndStoreCodexPrompts(repo); err != nil || added != 0 {
		t.Fatalf("scan after corrupt cache = %d, %v; want idempotent rebuild", added, err)
	}
	if matches, err := filepath.Glob(statePath + ".stale-*"); err != nil || len(matches) != 1 {
		t.Fatalf("stale scan-state quarantines = %v, %v; want one", matches, err)
	}
}

func TestCodexScanFailsClosedAfterMalformedJSONAndRecoversAfterRepair(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	writeCodexRollout(t, codexHome, "malformed.jsonl", []map[string]any{
		meta("malformed-session", repository.Root, nil),
		userMsg("2026-07-21T00:00:01Z", "valid prompt before malformed row"),
	})
	path := filepath.Join(codexHome, "sessions", "2026", "07", "21", "malformed.jsonl")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(userMsg("2026-07-21T00:00:02Z", "valid prompt after malformed row"))
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.Write(append([]byte("{malformed}\n"), append(after, '\n')...)); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	added, scanErr := scanAndStoreCodexPrompts(repo)
	if scanErr == nil || added != 1 {
		t.Fatalf("scan with malformed row = %d, %v; want only the prompt before corruption plus warning", added, scanErr)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil || len(events) != 1 {
		t.Fatalf("registry around malformed row = %d, %v; want 1", len(events), err)
	}

	writeCodexRollout(t, codexHome, "malformed.jsonl", []map[string]any{
		meta("malformed-session", repository.Root, nil),
		userMsg("2026-07-21T00:00:01Z", "valid prompt before malformed row"),
		userMsg("2026-07-21T00:00:01.500Z", "repaired prompt"),
		userMsg("2026-07-21T00:00:02Z", "valid prompt after malformed row"),
	})
	added, scanErr = scanAndStoreCodexPrompts(repo)
	if scanErr != nil || added != 2 {
		t.Fatalf("scan after malformed-row repair = %d, %v; want repaired and previously blocked prompts", added, scanErr)
	}
	events, err = readRegistryEvents(repository.Root)
	if err != nil || len(events) != 3 {
		t.Fatalf("registry after malformed-row repair = %d, %v; want 3", len(events), err)
	}
	counts := make(map[string]int)
	for _, event := range events {
		counts[event.Prompt]++
	}
	for _, prompt := range []string{
		"valid prompt before malformed row",
		"repaired prompt",
		"valid prompt after malformed row",
	} {
		if counts[prompt] != 1 {
			t.Fatalf("prompt %q appears %d times after repair; registry = %#v", prompt, counts[prompt], events)
		}
	}
}

func TestCodexScanCapturesFromRepoSubfoldersButNotNestedRepos(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)

	// A legitimate subfolder of THIS repository.
	ownSubdir := filepath.Join(repository.Root, "agent")
	if err := os.MkdirAll(ownSubdir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A different, nested Git repository checked in under this one.
	nestedRepo := filepath.Join(repository.Root, "reference-project")
	if err := os.MkdirAll(filepath.Join(nestedRepo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	nestedSub := filepath.Join(nestedRepo, "backend")
	if err := os.MkdirAll(nestedSub, 0o755); err != nil {
		t.Fatal(err)
	}

	writeCodexRollout(t, codexHome, "own.jsonl", []map[string]any{
		meta("sess-own", ownSubdir, nil),
		userMsg("2026-07-21T00:00:01Z", "prompt desde subcarpeta propia"),
	})
	writeCodexRollout(t, codexHome, "nested-root.jsonl", []map[string]any{
		meta("sess-nested", nestedRepo, nil),
		userMsg("2026-07-21T00:00:02Z", "prompt del proyecto anidado"),
	})
	writeCodexRollout(t, codexHome, "nested-sub.jsonl", []map[string]any{
		meta("sess-nested-sub", nestedSub, nil),
		userMsg("2026-07-21T00:00:03Z", "prompt de subcarpeta del anidado"),
	})

	repo, err := DiscoverRepository(repository.Nested)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanAndStoreCodexPrompts(repo); err != nil {
		t.Fatal(err)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("captured %d prompts, want 1 (only this repo's own subfolder)", len(events))
	}
	if !strings.Contains(events[0].Prompt, "subcarpeta propia") {
		t.Fatalf("captured the wrong prompt: %q", events[0].Prompt)
	}
}

func TestPathInRepoRejectsSymlinkThatEscapesRepository(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked-outside")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	if pathInRepo(filepath.Join(link, "child"), root) {
		t.Fatal("pathInRepo accepted a symbolic link that resolves outside the repository")
	}
}

func TestCodexCwdRejectsRelativePath(t *testing.T) {
	if scope := classifyProviderCWD(".", t.TempDir()); scope != providerPathOutside {
		t.Fatalf("relative cwd scope = %v; want outside", scope)
	}
	if codexCwdBelongsToRepo(".", t.TempDir()) {
		t.Fatal("codexCwdBelongsToRepo accepted a cwd relative to the recovery process")
	}
}

func TestCodexCwdRejectsDeletedSymlinkThatPreviouslyEscapedRepository(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked-outside")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	recordedCWD := filepath.Join(link, "child")
	if codexCwdBelongsToRepo(recordedCWD, root) {
		t.Fatal("codexCwdBelongsToRepo accepted a live symlink that escapes the repository")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if scope := classifyProviderCWD(recordedCWD, root); scope != providerPathIndeterminate {
		t.Fatalf("deleted symlink scope = %v; want indeterminate", scope)
	}
	if codexCwdBelongsToRepo(recordedCWD, root) {
		t.Fatal("codexCwdBelongsToRepo accepted a deleted symlink by lexical fallback")
	}
}

func TestCodexScannerReportsUnverifiableCwdInsideRepository(t *testing.T) {
	repoRoot := t.TempDir()
	missingCWD := filepath.Join(repoRoot, "deleted", "subdirectory")
	path := filepath.Join(t.TempDir(), "missing-cwd.jsonl")
	writeRawCodexFile(
		t,
		path,
		meta("repo-session", missingCWD, nil),
		userMsg("2026-07-21T00:00:01Z", "must remain blocked"),
	)

	prompts, scanErr := scanCodexFile(path, repoRoot)
	if scanErr == nil || len(prompts) != 0 || !strings.Contains(scanErr.Error(), "cwd cannot be verified") {
		t.Fatalf("unverifiable cwd = %#v, %v; want explicit health error", prompts, scanErr)
	}
}

func TestCodexCwdRejectsDanglingNestedGitMarker(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	nested := filepath.Join(root, "nested", "child")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "nested", ".git")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing-gitdir"), marker); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	if codexCwdBelongsToRepo(nested, root) {
		t.Fatal("codexCwdBelongsToRepo accepted a dangling nested .git marker")
	}
}

func TestCodexScanRevalidatesRepositoryScopeAfterEverySessionMetadataRecord(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)
	otherRepository := filepath.Join(t.TempDir(), "other-repository")
	if err := os.MkdirAll(filepath.Join(otherRepository, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	writeCodexRollout(t, codexHome, "scope-change.jsonl", []map[string]any{
		meta("scope-change", repository.Root, nil),
		userMsg("2026-07-21T00:00:01Z", "prompt propio antes del cambio"),
		meta("scope-change", otherRepository, nil),
		userMsg("2026-07-21T00:00:02Z", "prompt ajeno tras cambio de metadata"),
		meta("scope-change", repository.Nested, nil),
		userMsg("2026-07-21T00:00:03Z", "prompt propio tras volver"),
	})

	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanAndStoreCodexPrompts(repo); err != nil {
		t.Fatal(err)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("scope-changing rollout captured %d prompts, want 2", len(events))
	}
	for _, event := range events {
		if strings.Contains(event.Prompt, "ajeno") {
			t.Fatalf("out-of-scope prompt was imported: %q", event.Prompt)
		}
	}
}

func TestCodexScanIgnoresPromptsFromBeforeClone(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)

	// The project was "cloned" at 12:00; a prompt from 11:00 predates the clone.
	setTestCloneAnchor(t, repository.Root, time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	writeCodexRollout(t, codexHome, "rollout.jsonl", []map[string]any{
		meta("sess-mixed", repository.Root, nil),
		userMsg("2026-07-21T11:00:00Z", "prompt de ANTES del clon"),
		userMsg("2026-07-21T13:00:00Z", "prompt de DESPUES del clon"),
	})

	repo, err := DiscoverRepository(repository.Nested)
	if err != nil {
		t.Fatal(err)
	}
	added, err := scanAndStoreCodexPrompts(repo)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("captured %d prompts, want 1 (only the post-clone prompt)", added)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || !strings.Contains(events[0].Prompt, "DESPUES") {
		t.Fatalf("registry = %#v, want only the post-clone prompt", events)
	}
}

func TestCodexScanGroupsPromptsBySessionForTheReport(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := filepath.Join(t.TempDir(), "codex")
	t.Setenv("CODEX_HOME", codexHome)

	writeCodexRollout(t, codexHome, "rollout-a.jsonl", []map[string]any{
		meta("chat-A", repository.Root, nil),
		userMsg("2026-07-21T00:00:01Z", "primer prompt de A"),
		userMsg("2026-07-21T00:00:02Z", "segundo prompt de A"),
	})
	writeCodexRollout(t, codexHome, "rollout-b.jsonl", []map[string]any{
		meta("chat-B", repository.Root, nil),
		userMsg("2026-07-21T00:00:03Z", "prompt de B"),
	})

	if err := RecoverRegistry(repository.Nested); err != nil {
		t.Fatalf("RecoverRegistry() error = %v", err)
	}
	output := filepath.Join(t.TempDir(), "report.html")
	if _, err := GenerateReport(repository.Nested, output); err != nil {
		t.Fatalf("GenerateReport() error = %v", err)
	}
	html, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	content := string(html)
	for _, want := range []string{"chat-A", "chat-B", "primer prompt de A", "segundo prompt de A", "prompt de B"} {
		if !strings.Contains(content, want) {
			t.Fatalf("report missing %q", want)
		}
	}
}
