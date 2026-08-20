package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureCommandFailsClosedBeforeDurableStorageAndDoesNotLeakPrompt(t *testing.T) {
	const (
		prompt = "COMMAND-PROMPT-MUST-NOT-LEAK"
		secret = "COMMAND-RESPONSE-MUST-NOT-LEAK"
		token  = "COMMAND-TOKEN-MUST-NOT-LEAK"
	)
	// Build a dedicated repository so the test does not depend on the ambient
	// checkout (which may be a demo local_store project that captures without
	// touching external credentials).
	repositoryRoot := newCommandTestRepository(t)
	// A network failure after enqueue is deliberately silent because the prompt is
	// already durable. Use a pre-durability policy failure to exercise the CLI's
	// safe diagnostic and fail-open exit without creating credentials in the repo.
	configDir := filepath.Join(repositoryRoot, "forbidden config inside repository")
	payload := `{"hook_event_name":"UserPromptSubmit","transcript_path":"/tmp/session.jsonl","permission_mode":"default","cwd":"` + filepath.ToSlash(repositoryRoot) + `","prompt":"` + prompt + `","response":"` + secret + `","token":"` + token + `"}`
	result := runMainHelper(t, payload, "claude-code", configDir)
	var exitErr *exec.ExitError
	if !errors.As(result.err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("capture command exit = %v; want code 2; stderr=%q", result.err, result.stderr)
	}
	if !strings.Contains(result.stderr, "failed before durable storage") {
		t.Fatalf("stderr = %q, want safe durability diagnostic", result.stderr)
	}
	assertCommandTextExcludes(t, result.stdout+result.stderr, prompt, secret, token)
}

func TestCaptureCommandSilentlyIgnoresNonUserEvent(t *testing.T) {
	const secret = "ASSISTANT-EVENT-MUST-NOT-LEAK"
	payload := `{"hook_event_name":"Stop","response":"` + secret + `","prompt":"not-user-input"}`
	result := runMainHelper(t, payload, "claude-code", filepath.Join(t.TempDir(), "missing config"))
	if result.err != nil {
		t.Fatalf("capture command blocked its caller with nonzero exit: %v", result.err)
	}
	if result.stdout != "" || result.stderr != "" {
		t.Fatalf("non-user event produced output: stdout=%q stderr=%q", result.stdout, result.stderr)
	}
}

func TestCaptureCommandRejectsUnknownTool(t *testing.T) {
	const prompt = "UNKNOWN-TOOL-PROMPT-MUST-NOT-LEAK"
	result := runMainHelper(t, `{"prompt":"`+prompt+`"}`, "unknown-tool", filepath.Join(t.TempDir(), "missing config"))
	var exitErr *exec.ExitError
	if !errors.As(result.err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("unknown tool exit = %v; want code 2", result.err)
	}
	if !strings.Contains(result.stderr, "unknown tool") {
		t.Fatalf("stderr = %q, want unknown tool diagnostic", result.stderr)
	}
	assertCommandTextExcludes(t, result.stdout+result.stderr, prompt)
}

func newCommandTestRepository(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required for the capture command integration test")
	}
	root := filepath.Join(t.TempDir(), "repository with spaces")
	if err := os.MkdirAll(filepath.Join(root, ".devtools"), 0o755); err != nil {
		t.Fatal(err)
	}
	project := `{"server_url":"https://audit.example.invalid","organization_id":"example-co",` +
		`"project_name":"command-test","enabled_tools":["claude-code"],"retention_days":30,` +
		`"redact_secrets":true,"auto_enroll":true}`
	if err := os.WriteFile(filepath.Join(root, ".devtools", "project.json"), []byte(project), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("command test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCommandGit(t, root, "init")
	runCommandGit(t, root, "config", "user.name", "Command Test")
	runCommandGit(t, root, "config", "user.email", "command-test@example.invalid")
	runCommandGit(t, root, "add", ".")
	runCommandGit(t, root, "commit", "-m", "initial command test commit")
	return root
}

func runCommandGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

func TestCaptureMainHelper(t *testing.T) {
	if os.Getenv("PROMPT_AUDIT_TEST_MAIN_HELPER") != "1" {
		return
	}
	tool := os.Getenv("PROMPT_AUDIT_TEST_TOOL")
	os.Args = []string{"prompt-audit", "capture", "--tool", tool}
	main()
}

type commandResult struct {
	stdout string
	stderr string
	err    error
}

func runMainHelper(t *testing.T, stdin, tool, configDir string) commandResult {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCaptureMainHelper$")
	cmd.Env = append(os.Environ(),
		"PROMPT_AUDIT_TEST_MAIN_HELPER=1",
		"PROMPT_AUDIT_TEST_TOOL="+tool,
		"PROMPT_AUDIT_CONFIG_DIR="+configDir,
	)
	var fields map[string]any
	if json.Unmarshal([]byte(stdin), &fields) == nil {
		if cwd, ok := fields["cwd"].(string); ok && cwd != "" {
			cmd.Env = append(cmd.Env,
				"CLAUDE_PROJECT_DIR="+cwd,
				"PROMPT_AUDIT_REPOSITORY_ROOT="+cwd,
			)
		}
	}
	cmd.Stdin = strings.NewReader(stdin)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return commandResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func assertCommandTextExcludes(t *testing.T, text string, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if strings.Contains(text, value) {
			t.Errorf("command output leaked %q in %q", value, text)
		}
	}
}
