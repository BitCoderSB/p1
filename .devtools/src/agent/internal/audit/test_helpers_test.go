package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

func init() {
	// Integration tests exercise both the central and local implementations
	// with ephemeral HTTP servers. Production builds do not include _test.go
	// files and always enforce validateCompiledProjectPolicy.
	compiledProjectPolicyValidator = func(ProjectConfig) error { return nil }
	// Never spawn the detached recovery pass from a test binary: os.Executable()
	// would point at the test binary itself. Tests that need the recovery
	// behaviour call RunBackgroundBackfill directly.
	backgroundBackfillLauncher = func(string, []string, string, []string) error { return nil }
	// The runaway watchdog calls os.Exit; arming it inside the test binary
	// would kill the suite.
	stopRunawayBackfill = func(time.Duration) {}
	// View commands recover synchronously in production. Tests that exercise
	// that path install their own scan; by default it is a no-op so an
	// unrelated test never scans the developer's real provider history.
	recoverForViewingBestEffort = func(RepositoryInfo) {}
}

func writeEventAcknowledgement(w http.ResponseWriter, eventID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(model.EventResponse{Accepted: true, EventID: eventID})
}

func acknowledgeEventRequest(w http.ResponseWriter, r *http.Request) {
	var event model.Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid event", http.StatusBadRequest)
		return
	}
	writeEventAcknowledgement(w, event.EventID)
}

type testRepository struct {
	Root       string
	Nested     string
	Branch     string
	CommitHash string
	Remote     string
}

func newTestRepository(t *testing.T, serverURL string, _ []string) testRepository {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required for repository integration tests")
	}

	root := filepath.Join(t.TempDir(), "repository with spaces")
	nested := filepath.Join(root, "nested folder", "deeper")
	if err := os.MkdirAll(filepath.Join(root, ".devtools"), 0o755); err != nil {
		t.Fatalf("create project configuration directory: %v", err)
	}
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("create nested working directory: %v", err)
	}

	project := ProjectConfig{
		ServerURL:      serverURL,
		OrganizationID: compiledOrganizationID,
		ProjectName:    compiledProjectName,
		EnabledTools: []string{
			model.ToolClaudeCode,
			model.ToolCodex,
			model.ToolCopilotCLI,
		},
		RetentionDays: 30,
		RedactSecrets: true,
	}
	encoded, err := json.MarshalIndent(project, "", "  ")
	if err != nil {
		t.Fatalf("encode project configuration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(projectConfigPath)), encoded, 0o600); err != nil {
		t.Fatalf("write project configuration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("test repository\n"), 0o600); err != nil {
		t.Fatalf("write repository fixture: %v", err)
	}
	writeTestProviderFiles(t, root, project.EnabledTools)
	writeTestCodexExecutable(t, root)

	runGit(t, root, "init")
	runGit(t, root, "config", "user.name", "Prompt Audit Tests")
	runGit(t, root, "config", "user.email", "tests@example.invalid")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "initial test commit")
	remote := "https://remote-user:remote-password@example.invalid/acme/repository.git"
	runGit(t, root, "remote", "add", "origin", remote)
	t.Setenv(captureRepositoryRootEnv, root)

	return testRepository{
		Root:       root,
		Nested:     nested,
		Branch:     runGit(t, root, "symbolic-ref", "--quiet", "--short", "HEAD"),
		CommitHash: runGit(t, root, "rev-parse", "--verify", "HEAD"),
		Remote:     remote,
	}
}

func writeTestCodexExecutable(t *testing.T, root string) {
	t.Helper()
	directory := filepath.Join(root, ".test-bin")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatalf("create fake Codex directory: %v", err)
	}
	name := "codex"
	contents := []byte("#!/bin/sh\nprintf '%s\\n' 'codex-cli 0.142.5'\n")
	mode := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		name = "codex.cmd"
		contents = []byte("@echo off\r\necho codex-cli 0.142.5\r\n")
		mode = 0o600
	}
	if err := os.WriteFile(filepath.Join(directory, name), contents, mode); err != nil {
		t.Fatalf("write fake Codex executable: %v", err)
	}
	claudeName := "claude"
	claudeContents := []byte("#!/bin/sh\nprintf '%s\\n' '2.1.216 (Claude Code)'\n")
	claudeMode := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		claudeName = "claude.cmd"
		claudeContents = []byte("@echo off\r\necho 2.1.216 (Claude Code)\r\n")
		claudeMode = 0o600
	}
	if err := os.WriteFile(filepath.Join(directory, claudeName), claudeContents, claudeMode); err != nil {
		t.Fatalf("write fake Claude executable: %v", err)
	}
	copilotName := "copilot"
	copilotContents := []byte("#!/bin/sh\nprintf '%s\\n' '1.0.75'\n")
	copilotMode := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		copilotName = "copilot.cmd"
		copilotContents = []byte("@echo off\r\necho 1.0.75\r\n")
		copilotMode = 0o600
	}
	if err := os.WriteFile(filepath.Join(directory, copilotName), copilotContents, copilotMode); err != nil {
		t.Fatalf("write fake Copilot executable: %v", err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func writeTestProviderFiles(t *testing.T, root string, enabledTools []string) {
	t.Helper()
	writeBytes := func(relative string, contents []byte, mode os.FileMode) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create provider fixture directory: %v", err)
		}
		if err := os.WriteFile(path, contents, mode); err != nil {
			t.Fatalf("write provider fixture %s: %v", relative, err)
		}
	}
	write := func(relative, contents string) {
		t.Helper()
		writeBytes(relative, []byte(contents), 0o600)
	}
	_, helperPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate provider test fixtures")
	}
	devtoolsRoot := filepath.Clean(filepath.Join(filepath.Dir(helperPath), "..", "..", "..", ".."))
	for _, wrapper := range []struct {
		source   string
		relative string
		mode     os.FileMode
	}{
		{source: "setup", relative: ".devtools/setup", mode: 0o755},
		{source: "setup.cmd", relative: ".devtools/setup.cmd", mode: 0o600},
	} {
		contents, err := os.ReadFile(filepath.Join(devtoolsRoot, wrapper.source))
		if err != nil {
			t.Fatalf("read canonical provider fixture %s: %v", wrapper.source, err)
		}
		writeBytes(wrapper.relative, contents, wrapper.mode)
	}
	canonicalRoot := filepath.Dir(devtoolsRoot)
	instruction, err := os.ReadFile(filepath.Join(canonicalRoot, ".claude", "CLAUDE.md"))
	if err != nil {
		t.Fatalf("read canonical bootstrap instruction: %v", err)
	}
	codexInstruction, err := os.ReadFile(filepath.Join(canonicalRoot, ".codex", "AGENTS.md"))
	if err != nil {
		t.Fatalf("read canonical Codex instruction: %v", err)
	}
	for _, tool := range enabledTools {
		command := providerCaptureCommand + tool
		switch tool {
		case model.ToolClaudeCode:
			write(".claude/settings.json", fmt.Sprintf(
				`{"disableAllHooks":false,"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":%q,"timeout":15}]}],"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"timeout":30}]}]}}`,
				providerBootstrapCommand, command,
			))
			writeBytes(".claude/CLAUDE.md", instruction, 0o600)
		case model.ToolCodex:
			write(".codex/config.toml", "project_doc_fallback_filenames = [\".codex/AGENTS.md\"]\n\n[features]\nhooks = true\n")
			write(".codex/hooks.json", fmt.Sprintf(
				`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":%q,"commandWindows":%q,"timeout":15}]}],"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"commandWindows":%q,"timeout":30}]}]}}`,
				providerBootstrapCommand, providerBootstrapCommand, command, command,
			))
			writeBytes(".codex/AGENTS.md", codexInstruction, 0o600)
		case model.ToolCopilotCLI:
			write(".github/hooks/prompt-audit.json", fmt.Sprintf(
				`{"version":1,"disableAllHooks":false,"hooks":{"SessionStart":[{"type":"command","command":%q,"cwd":".","timeout":15}],"UserPromptSubmit":[{"type":"command","command":%q,"cwd":".","timeout":30}]}}`,
				providerBootstrapCommand, command,
			))
			write(".github/copilot/settings.json", `{"disableAllHooks":false}`)
			writeBytes(".github/copilot-instructions.md", instruction, 0o600)
			write(".vscode/settings.json", `{"chat.hookFilesLocations":{".github/hooks":true,".claude/settings.json":false,".claude/settings.local.json":false,"~/.claude/settings.json":false}}`)
		}
	}
}

func setTestProjectAutoEnroll(t *testing.T, repository testRepository, enabled bool) ProjectConfig {
	t.Helper()
	project, err := loadProjectConfig(repository.Root)
	if err != nil {
		t.Fatalf("load project configuration: %v", err)
	}
	if project.AutoEnroll == enabled {
		return project
	}
	project.AutoEnroll = enabled
	encoded, err := json.MarshalIndent(project, "", "  ")
	if err != nil {
		t.Fatalf("encode project configuration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repository.Root, filepath.FromSlash(projectConfigPath)), encoded, 0o600); err != nil {
		t.Fatalf("write project configuration: %v", err)
	}
	runGit(t, repository.Root, "add", filepath.FromSlash(projectConfigPath))
	runGit(t, repository.Root, "commit", "-m", "configure automatic enrollment")
	return project
}

func openTestProjectQueue(t *testing.T, project ProjectConfig) *Queue {
	t.Helper()
	profile, err := projectProfileKey(project)
	if err != nil {
		t.Fatalf("project profile key: %v", err)
	}
	queue, err := openQueueForProfile(profile)
	if err != nil {
		t.Fatalf("open project queue: %v", err)
	}
	return queue
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", commandArgs...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

func samePath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func useTestConfigDirectory(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "user config with spaces")
	t.Setenv("PROMPT_AUDIT_CONFIG_DIR", dir)
	providerRoot := filepath.Join(t.TempDir(), "isolated provider histories")
	t.Setenv("CODEX_HOME", filepath.Join(providerRoot, "codex"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(providerRoot, "claude"))
	t.Setenv("APPDATA", filepath.Join(providerRoot, "appdata"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(providerRoot, "xdg"))
	return dir
}

func writeTestUserConfig(t *testing.T, dir string, cfg UserConfig) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create user configuration directory: %v", err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("encode user configuration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, userConfigFileName), encoded, 0o600); err != nil {
		t.Fatalf("write user configuration: %v", err)
	}
}

func sampleEvent(id, prompt string) model.Event {
	return model.Event{
		EventID:          id,
		Timestamp:        time.Date(2026, 7, 19, 18, 30, 0, 0, time.UTC),
		UserID:           "user-1",
		UserEmail:        "worker@example.invalid",
		Tool:             model.ToolClaudeCode,
		RepositoryName:   "inventory",
		RepositoryRemote: "example.invalid/acme/inventory",
		Branch:           "feature/login",
		CommitHash:       "0123456789abcdef",
		SessionID:        "session-1",
		Prompt:           prompt,
	}
}
