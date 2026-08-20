package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

func writeClaudeRecord(t *testing.T, file *os.File, value any) {
	t.Helper()
	line, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
}

func claudeUserRecord(cwd, timestamp, prompt string) map[string]any {
	return map[string]any{
		"type": "user", "timestamp": timestamp, "cwd": cwd,
		"origin":  map[string]any{"kind": "human"},
		"message": map[string]any{"content": prompt},
	}
}

func TestClaudeScannerScopesEveryTurnAndKeepsValidRowsAroundCorruption(t *testing.T) {
	const assistantSecret = "CLAUDE-ASSISTANT-MUST-NOT-BE-STORED"
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	configDir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	sessionDir := filepath.Join(configDir, "projects", "fixture")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sessionDir, "claude-fixture.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writeClaudeRecord(t, file, claudeUserRecord(repository.Root, "2026-07-21T00:00:01Z", "first project prompt"))
	writeClaudeRecord(t, file, map[string]any{
		"type": "assistant", "timestamp": "2026-07-21T00:00:02Z", "cwd": repository.Root,
		"message": map[string]any{"content": assistantSecret},
	})
	writeClaudeRecord(t, file, claudeUserRecord(t.TempDir(), "2026-07-21T00:00:03Z", "prompt from another project"))
	if _, err := file.WriteString("{malformed}\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	writeClaudeRecord(t, file, claudeUserRecord(repository.Nested, "2026-07-21T00:00:04Z", "second project prompt"))
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	added, scanErr := scanAndStoreClaudePrompts(repo)
	if scanErr == nil || added != 2 {
		t.Fatalf("Claude scan = %d, %v; want two prompts plus corruption warning", added, scanErr)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil || len(events) != 2 {
		t.Fatalf("Claude registry = %d, %v; want 2", len(events), err)
	}
	var joined strings.Builder
	for _, event := range events {
		joined.WriteString(event.Prompt)
		joined.WriteByte('\n')
	}
	if strings.Contains(joined.String(), assistantSecret) || strings.Contains(joined.String(), "another project") {
		t.Fatalf("Claude scanner crossed scope or captured assistant output: %q", joined.String())
	}
	if !strings.Contains(joined.String(), "first project prompt") || !strings.Contains(joined.String(), "second project prompt") {
		t.Fatalf("Claude scanner lost valid project prompts: %q", joined.String())
	}
}

func TestClaudeScannerReportsMalformedHumanMessageInRepositoryScope(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "claude-malformed-message.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writeClaudeRecord(t, file, map[string]any{
		"type": "user", "timestamp": "2026-07-21T00:00:01Z", "cwd": repoRoot,
		"origin": map[string]any{"kind": "human"}, "message": nil,
	})
	writeClaudeRecord(t, file, claudeUserRecord(repoRoot, "2026-07-21T00:00:02Z", "valid prompt after malformed message"))
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	prompts, scanErr := scanClaudeFile(path, repoRoot)
	if scanErr == nil || len(prompts) != 1 || prompts[0].Prompt != "valid prompt after malformed message" {
		t.Fatalf("scanClaudeFile() = %#v, %v; want one prompt plus health error", prompts, scanErr)
	}
}

func TestClaudeFilePagingEventuallyReturnsEveryPrompt(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(t.TempDir(), "claude-paged.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 5; index++ {
		writeClaudeRecord(
			t,
			file,
			claudeUserRecord(
				repoRoot,
				time.Date(2026, 7, 21, 0, 0, index+1, 0, time.UTC).Format(time.RFC3339),
				fmt.Sprintf("claude-page-%d", index+1),
			),
		)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	startLine := 1
	var positions []int
	for page := 0; page < 3; page++ {
		prompts, nextLine, scanErr := scanClaudeFilePage(
			path,
			repoRoot,
			startLine,
			newRecoveredPromptCollectorWithLimits(2, 1024, 512),
		)
		if scanErr != nil {
			t.Fatal(scanErr)
		}
		for _, prompt := range prompts {
			positions = append(positions, prompt.Position)
		}
		startLine = nextLine
	}
	if fmt.Sprint(positions) != "[1 2 3 4 5]" || startLine != 0 {
		t.Fatalf("Claude pages = %v, next=%d; want all prompts and completion", positions, startLine)
	}
}

func TestClaudeRecoveryRetriesCwdThatBecomesResolvable(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	configDir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	sessionDir := filepath.Join(configDir, "projects", "fixture")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	recordedCWD := filepath.Join(repository.Root, "created-after-first-scan")
	path := filepath.Join(sessionDir, "claude-late-cwd.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writeClaudeRecord(
		t,
		file,
		claudeUserRecord(
			recordedCWD,
			"2026-07-21T00:00:01Z",
			"prompt whose cwd becomes resolvable",
		),
	)
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	added, scanErr := scanAndStoreClaudePrompts(repo)
	if added != 0 || scanErr == nil {
		t.Fatalf("unresolved cwd scan = %d, %v; want 0 plus diagnostic", added, scanErr)
	}
	if err := os.MkdirAll(recordedCWD, 0o700); err != nil {
		t.Fatal(err)
	}
	added, scanErr = scanAndStoreClaudePrompts(repo)
	if added != 1 || scanErr != nil {
		t.Fatalf("resolved cwd scan = %d, %v; want 1, nil", added, scanErr)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Prompt != "prompt whose cwd becomes resolvable" {
		t.Fatalf("resolved cwd events = %#v; want the deferred prompt", events)
	}
}
