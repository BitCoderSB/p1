package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acme/prompt-audit-template/internal/model"
)

func TestSaveUserConfigAtomicallyReplacesCompleteCredential(t *testing.T) {
	dir := useTestConfigDirectory(t)
	cfg := UserConfig{
		UserID: "worker-atomic", Name: "Atomic Worker", Email: "atomic@example.invalid",
		ServerURL: "https://audit.example.invalid", Token: "first-token",
	}
	if err := SaveUserConfig(cfg); err != nil {
		t.Fatalf("first SaveUserConfig: %v", err)
	}
	cfg.Token = "second-token"
	if err := SaveUserConfig(cfg); err != nil {
		t.Fatalf("replacement SaveUserConfig: %v", err)
	}
	loaded, err := LoadUserConfig()
	if err != nil || loaded.Token != cfg.Token {
		t.Fatalf("LoadUserConfig = %#v, %v", loaded, err)
	}
	contents, err := os.ReadFile(filepath.Join(dir, userConfigFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "first-token") {
		t.Fatal("replacement left the previous credential in the active file")
	}
	temps, err := filepath.Glob(filepath.Join(dir, ".config-*.tmp"))
	if err != nil || len(temps) != 0 {
		t.Fatalf("temporary credential files = %v, %v", temps, err)
	}
}

func TestConfigDirectoryOverrideMustBeAbsolute(t *testing.T) {
	t.Setenv("PROMPT_AUDIT_CONFIG_DIR", ".devtools-credentials")
	if _, err := configDir(); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("configDir error = %v, want absolute-path refusal", err)
	}
}

func TestStatusReportsConfigurationAndQueueWithoutTokenOrPrompt(t *testing.T) {
	// Run outside any repository so Status reports the legacy global credential and
	// queue this test targets, independent of the ambient checkout (which may itself
	// be a demo local_store project).
	t.Chdir(t.TempDir())
	configDir := useTestConfigDirectory(t)
	const (
		token  = "STATUS-TOKEN-MUST-NOT-LEAK"
		prompt = "STATUS-PROMPT-MUST-NOT-LEAK"
	)
	writeTestUserConfig(t, configDir, UserConfig{
		UserID:    "worker-status-id",
		Name:      "Status Worker",
		Email:     "status@example.invalid",
		ServerURL: "https://audit.example.invalid",
		Token:     token,
	})
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(sampleEvent("status-event", prompt)); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := Status(&output); err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	text := output.String()
	for _, want := range []string{
		"Status Worker",
		"status@example.invalid",
		"worker-status-id",
		"https://audit.example.invalid",
		"Token: configurado (oculto)",
		"Eventos pendientes: 1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Status output %q omitted %q", text, want)
		}
	}
	assertTextExcludes(t, text, token, prompt)
}

// status is the administrator's diagnostic: it restores a missing capture hook
// and says so, rather than only reporting that something is wrong.
func TestStatusRestoresMissingProviderPromptHook(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCopilotCLI})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	t.Chdir(repository.Root)
	path := filepath.Join(repository.Root, ".github", "hooks", "prompt-audit.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Status(&output); err != nil {
		t.Fatalf("Status() with a missing capture hook = %v", err)
	}
	if !strings.Contains(output.String(), "restauró") {
		t.Fatalf("Status() must report the repair: %q", output.String())
	}
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatalf("discover repository: %v", err)
	}
	if err := verifyProviderCaptureConfiguration(repo); err != nil {
		t.Fatalf("the capture hook must be restored: %v", err)
	}
}

func TestStatusFailsWhenPreCommitDeliveryHookIsForeign(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	t.Chdir(repository.Root)

	hookPath := filepath.Join(repository.Root, ".git", "hooks", "pre-commit")
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	err := Status(&output)
	if err == nil || !strings.Contains(err.Error(), "pre-commit delivery hook is unavailable") {
		t.Fatalf("Status() with foreign delivery hook = %v, want explicit failure", err)
	}
	if !strings.Contains(output.String(), "Prompts registrados:") {
		t.Fatalf("Status() omitted safe counts while degraded: %q", output.String())
	}
}

func TestStatusDoesNotScanBrokenPromptHistory(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	t.Chdir(repository.Root)

	sessionDirectory := filepath.Join(os.Getenv("CLAUDE_CONFIG_DIR"), "projects", "repository")
	if err := os.MkdirAll(sessionDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(sessionDirectory, "broken-session.jsonl"),
		[]byte("{not-json}\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	err := Status(&output)
	if err != nil {
		t.Fatalf("Status() scanned or failed on unrelated prompt history: %v", err)
	}
	if !strings.Contains(output.String(), "Prompts registrados: 0") {
		t.Fatalf("Status() reported an implicit history import: %q", output.String())
	}
}

func TestStatusFailsInsideRepositoryWithInvalidProjectConfig(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	useTestConfigDirectory(t)
	t.Chdir(repository.Root)
	if err := os.WriteFile(
		filepath.Join(repository.Root, filepath.FromSlash(projectConfigPath)),
		[]byte(`{"organization_id":"redirected"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Status(&output); err == nil ||
		!strings.Contains(err.Error(), "configuration is invalid") {
		t.Fatalf("Status() with invalid project policy = %v, want explicit failure", err)
	}
}

func TestLoadUserConfigErrorsDoNotEchoToken(t *testing.T) {
	configDir := useTestConfigDirectory(t)
	const token = "MALFORMED-CONFIG-TOKEN-MUST-NOT-LEAK"
	writeTestUserConfig(t, configDir, UserConfig{
		UserID:    "worker",
		Email:     "worker@example.invalid",
		ServerURL: "https://user:" + token + "@audit.example.invalid",
		Token:     token,
	})
	_, err := LoadUserConfig()
	if err == nil {
		t.Fatal("LoadUserConfig() unexpectedly accepted URL credentials")
	}
	assertTextExcludes(t, err.Error(), token)
}
