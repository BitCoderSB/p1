package audit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

func writeProviderHardeningFixture(t *testing.T, root, relative, contents string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create provider hardening fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write provider hardening fixture: %v", err)
	}
	return path
}

// Claude and Copilot run their project hooks on their own, so their instruction
// files stay passive and identical. Codex is the exception on purpose: its hooks
// do not run until approved, so its file carries a one-time activation the agent
// performs on the first prompt of a fresh clone, guarded by the .initialized
// marker so it happens once per clone and never again.
func TestProviderInstructionsMatchTheirHookModel(t *testing.T) {
	_, helperPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate canonical provider instructions")
	}
	repositoryRoot := filepath.Clean(filepath.Join(
		filepath.Dir(helperPath),
		"..", "..", "..", "..", "..",
	))
	read := func(relative string) string {
		contents, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		return string(contents)
	}

	// Claude and Copilot: passive, identical, and never asking the agent to run
	// a command — their hooks already capture.
	claude := read(".claude/CLAUDE.md")
	copilot := read(".github/copilot-instructions.md")
	if claude != copilot {
		t.Fatal(".claude/CLAUDE.md and .github/copilot-instructions.md must stay identical")
	}
	for _, relative := range []string{".claude/CLAUDE.md", ".github/copilot-instructions.md"} {
		text := read(relative)
		if !strings.Contains(text, "automáticamente una sola vez") {
			t.Fatalf("%s does not describe automatic single activation", relative)
		}
		for _, forbidden := range []string{"setup bootstrap", "setup.cmd bootstrap"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s must not order the agent to run a command; its hook already captures", relative)
			}
		}
	}

	// Codex: the one file that instructs a one-time, marker-guarded activation.
	codex := read(".codex/AGENTS.md")
	if codex == claude {
		t.Fatal(".codex/AGENTS.md must differ: Codex hooks need a one-time agent activation")
	}
	if !strings.Contains(codex, "setup.cmd bootstrap") || !strings.Contains(codex, "./.devtools/setup bootstrap") {
		t.Fatal(".codex/AGENTS.md must tell the agent how to activate on both platforms")
	}
	if !strings.Contains(codex, ".initialized") {
		t.Fatal(".codex/AGENTS.md must guard activation with the .initialized marker so it runs once per clone")
	}

	// Regression guard. An earlier revision led with "no uses la terminal, no
	// ejecutes ningún comando" as the headline and buried the activation branch
	// underneath. The agent applied the prohibition to everything and never
	// activated a fresh clone, so nothing was captured at all. The instruction
	// to act must come before any preference about how to check.
	if strings.Index(codex, "setup.cmd bootstrap") < 0 {
		t.Fatal(".codex/AGENTS.md lost its activation command")
	}
	if !strings.Contains(codex, "Activación del registro: obligatoria") {
		t.Fatal(".codex/AGENTS.md must state that activation is obligatory once per clone")
	}

	// The instruction must never steer the agent away from the terminal.
	// Codex reported it directly: it has no dedicated file-reading tool, so
	// reading a file IS a terminal command for it. Asking it to check "without
	// the terminal" is impossible to satisfy, and it resolved the contradiction
	// by skipping activation entirely — a fresh clone captured nothing.
	for _, impossible := range []string{
		"no la terminal",
		"No uses la terminal",
		"No ejecutes ningun comando",
		"No ejecutes ningún comando",
		"Comprobacion sin comandos",
		"Comprobación sin comandos",
		"herramienta de lectura",
	} {
		if strings.Contains(codex, impossible) {
			t.Fatalf(
				"%q asks Codex for a capability it does not have; it skips activation instead",
				impossible,
			)
		}
	}
	// And it must say so positively, so a missing tool is never taken as a
	// reason to skip the step.
	if !strings.Contains(codex, "la terminal es válida para esta comprobación") {
		t.Fatal(".codex/AGENTS.md must state that the terminal is an acceptable way to check")
	}
	if !strings.Contains(codex, "Nunca omitas esta comprobación") {
		t.Fatal(".codex/AGENTS.md must forbid skipping the check for lack of a tool")
	}
}

func installProviderTestCodex(t *testing.T, versionOutput string) {
	t.Helper()
	directory := t.TempDir()
	name := "codex"
	contents := []byte("#!/bin/sh\nprintf '%s\\n' '" + versionOutput + "'\n")
	mode := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		name = "codex.cmd"
		contents = []byte("@echo off\r\necho " + versionOutput + "\r\n")
		mode = 0o600
	}
	if err := os.WriteFile(filepath.Join(directory, name), contents, mode); err != nil {
		t.Fatalf("write Codex runtime fixture: %v", err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func installProviderTestClaude(t *testing.T, versionOutput string) {
	t.Helper()
	directory := t.TempDir()
	name := "claude"
	contents := []byte("#!/bin/sh\nprintf '%s\\n' '" + versionOutput + "'\n")
	mode := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		name = "claude.cmd"
		contents = []byte("@echo off\r\necho " + versionOutput + "\r\n")
		mode = 0o600
	}
	if err := os.WriteFile(filepath.Join(directory, name), contents, mode); err != nil {
		t.Fatalf("write Claude runtime fixture: %v", err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func installProviderTestCopilot(t *testing.T, versionOutput string) {
	t.Helper()
	directory := t.TempDir()
	name := "copilot"
	contents := []byte("#!/bin/sh\nprintf '%s\\n' '" + versionOutput + "'\n")
	mode := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		name = "copilot.cmd"
		contents = []byte("@echo off\r\necho " + versionOutput + "\r\n")
		mode = 0o600
	}
	if err := os.WriteFile(filepath.Join(directory, name), contents, mode); err != nil {
		t.Fatalf("write Copilot runtime fixture: %v", err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestVerifyCodexProjectConfigRejectsNonCanonicalVariants(t *testing.T) {
	const canonical = "project_doc_fallback_filenames = [\".codex/AGENTS.md\"]\n\n[features]\nhooks = true\n"
	for _, testCase := range []struct {
		name     string
		contents string
	}{
		{
			name:     "duplicate hooks assignment",
			contents: canonical + "\n[features]\nhooks = true\n",
		},
		{
			name:     "truncated",
			contents: strings.TrimSuffix(canonical, "true\n"),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			path := writeProviderHardeningFixture(
				t,
				root,
				".codex/config.toml",
				testCase.contents,
			)
			if err := verifyCodexProjectConfig(root, path); err == nil {
				t.Fatalf("verifyCodexProjectConfig() accepted %s configuration", testCase.name)
			}
		})
	}
}

func TestVerifyCodexRuntimeRequiresAvailableStableMinimum(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if err := verifyCodexRuntimeVersion(); err == nil ||
			!strings.Contains(err.Error(), "unavailable") {
			t.Fatalf("verifyCodexRuntimeVersion() with missing executable = %v", err)
		}
	})
	for _, testCase := range []struct {
		name          string
		versionOutput string
		wantError     bool
	}{
		{name: "old", versionOutput: "codex-cli 0.133.99", wantError: true},
		{name: "prerelease", versionOutput: "codex-cli 0.134.0-rc.1", wantError: true},
		{name: "later prerelease remains unsupported", versionOutput: "codex-cli 0.145.0-alpha.18", wantError: true},
		{name: "unrelated semver", versionOutput: "dependency 99.0.0", wantError: true},
		{name: "minimum stable", versionOutput: "codex-cli 0.134.0"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			installProviderTestCodex(t, testCase.versionOutput)
			err := verifyCodexRuntimeVersion()
			if testCase.wantError && err == nil {
				t.Fatalf("verifyCodexRuntimeVersion() accepted %q", testCase.versionOutput)
			}
			if !testCase.wantError && err != nil {
				t.Fatalf("verifyCodexRuntimeVersion() rejected %q: %v", testCase.versionOutput, err)
			}
		})
	}
}

func TestVerifyInstalledProviderRuntimeAllowsUninstalledOtherClients(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	called := false
	if err := verifyInstalledProviderRuntime("provider-not-installed", func() error {
		called = true
		return errors.New("must not run")
	}); err != nil {
		t.Fatalf("verifyInstalledProviderRuntime() with absent unrelated client = %v", err)
	}
	if called {
		t.Fatal("verifyInstalledProviderRuntime called verifier for an absent client")
	}
}

func TestVerifyClaudeRuntimeRequiresAvailableStableMinimum(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if err := verifyClaudeRuntimeVersion(); err == nil ||
			!strings.Contains(err.Error(), "unavailable") {
			t.Fatalf("verifyClaudeRuntimeVersion() with missing executable = %v", err)
		}
	})
	for _, testCase := range []struct {
		name          string
		versionOutput string
		wantError     bool
	}{
		{name: "old", versionOutput: "1.0.57 (Claude Code)", wantError: true},
		{name: "prerelease", versionOutput: "1.0.58-rc.1 (Claude Code)", wantError: true},
		{name: "unrelated semver", versionOutput: "dependency 99.0.0", wantError: true},
		{name: "old with unrelated newer dependency", versionOutput: "Claude Code 0.9.0 Node 20.0.0", wantError: true},
		{name: "minimum stable", versionOutput: "1.0.58 (Claude Code)"},
		{name: "product first", versionOutput: "Claude Code 1.0.58"},
		{name: "hyphenated product", versionOutput: "claude-code 1.0.58"},
		{name: "current format", versionOutput: "2.1.216 (Claude Code)"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			installProviderTestClaude(t, testCase.versionOutput)
			err := verifyClaudeRuntimeVersion()
			if testCase.wantError && err == nil {
				t.Fatalf("verifyClaudeRuntimeVersion() accepted %q", testCase.versionOutput)
			}
			if !testCase.wantError && err != nil {
				t.Fatalf("verifyClaudeRuntimeVersion() rejected %q: %v", testCase.versionOutput, err)
			}
		})
	}
}

func TestVerifyCopilotRuntimeRequiresAvailableStableMinimum(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if err := verifyCopilotRuntimeVersion(); err == nil ||
			!strings.Contains(err.Error(), "unavailable") {
			t.Fatalf("verifyCopilotRuntimeVersion() with missing executable = %v", err)
		}
	})
	for _, testCase := range []struct {
		name          string
		versionOutput string
		wantError     bool
	}{
		{name: "old", versionOutput: "1.0.21", wantError: true},
		{name: "prerelease", versionOutput: "1.0.22-rc.1", wantError: true},
		{name: "decorated output", versionOutput: "Copilot CLI 99.0.0", wantError: true},
		{name: "minimum stable", versionOutput: "1.0.22"},
		{name: "version prefix", versionOutput: "v1.0.22"},
		{name: "current stable", versionOutput: "1.0.75"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			installProviderTestCopilot(t, testCase.versionOutput)
			err := verifyCopilotRuntimeVersion()
			if testCase.wantError && err == nil {
				t.Fatalf("verifyCopilotRuntimeVersion() accepted %q", testCase.versionOutput)
			}
			if !testCase.wantError && err != nil {
				t.Fatalf("verifyCopilotRuntimeVersion() rejected %q: %v", testCase.versionOutput, err)
			}
		})
	}
}

func TestAutomaticCaptureActivationDoesNotLaunchProviderRuntime(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	installProviderTestCodex(t, "codex-cli 0.1.0")

	if err := ReconcileRegistry(repository.Root); err != nil {
		t.Fatalf("ReconcileRegistry() was blocked by a runtime probe: %v", err)
	}
	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() launched or was blocked by installed Codex: %v", err)
	}

	t.Chdir(repository.Root)
	out.Reset()
	if err := Status(&out); err == nil ||
		!strings.Contains(err.Error(), "verify Codex runtime") {
		t.Fatalf("Status() with incompatible installed Codex = %v, want explicit diagnostic", err)
	}
}

func TestAutomaticCaptureActivationDoesNotLaunchUnavailableProviderRuntime(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)

	directory := t.TempDir()
	name := "codex"
	contents := []byte("#!/bin/sh\nexit 91\n")
	mode := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		name = "codex.cmd"
		contents = []byte("@echo off\r\nexit /b 91\r\n")
		mode = 0o600
	}
	if err := os.WriteFile(filepath.Join(directory, name), contents, mode); err != nil {
		t.Fatalf("write unavailable Codex probe fixture: %v", err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))

	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() launched or was blocked by unavailable Codex: %v", err)
	}
	t.Chdir(repository.Root)
	out.Reset()
	if err := Status(&out); err == nil ||
		!strings.Contains(err.Error(), "provider runtime probe is unavailable") {
		t.Fatalf("Status() with unavailable Codex probe = %v, want explicit diagnostic", err)
	}
}

func TestCodexVersionOutputIsCapped(t *testing.T) {
	output := cappedOutput{remaining: 4096}
	contents := bytes.Repeat([]byte("x"), 8192)
	written, err := output.Write(contents)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(contents) {
		t.Fatalf("cappedOutput.Write() = %d, want %d consumed bytes", written, len(contents))
	}
	if got := len(output.String()); got != 4096 {
		t.Fatalf("cappedOutput retained %d bytes, want exactly 4096", got)
	}
}

func TestProviderVersionTimeoutKillsCommandShimTree(t *testing.T) {
	directory := t.TempDir()
	name := "slow-provider"
	contents := []byte("#!/bin/sh\nsleep 30\n")
	mode := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		name += ".cmd"
		contents = []byte("@echo off\r\npowershell.exe -NoLogo -NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 30\"\r\n")
		mode = 0o600
	}
	if err := os.WriteFile(filepath.Join(directory, name), contents, mode); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))

	started := time.Now()
	_, err := runProviderVersionCommandWithTimeout(
		"slow-provider",
		200*time.Millisecond,
		"--version",
	)
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "version check exceeded") {
		t.Fatalf("slow provider error = %v, want bounded timeout", err)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("provider process tree remained attached for %s after timeout", elapsed)
	}
}

func TestProviderHooksRequireExactEventTimeouts(t *testing.T) {
	captureClaude := providerCaptureCommand + model.ToolClaudeCode
	captureCodex := providerCaptureCommand + model.ToolCodex
	captureCopilot := providerCaptureCommand + model.ToolCopilotCLI
	for _, testCase := range []struct {
		name     string
		relative string
		contents string
		verify   func(string, string) error
	}{
		{
			name:     "Claude 29",
			relative: ".claude/settings.json",
			contents: fmt.Sprintf(
				`{"disableAllHooks":false,"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":%q,"timeout":15}]}],"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"timeout":29}]}]}}`,
				providerBootstrapCommand,
				captureClaude,
			),
			verify: func(root, path string) error {
				return verifyCommandHookJSON(root, path, "UserPromptSubmit", captureClaude, false)
			},
		},
		{
			name:     "Claude 31",
			relative: ".claude/settings.json",
			contents: fmt.Sprintf(
				`{"disableAllHooks":false,"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":%q,"timeout":15}]}],"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"timeout":31}]}]}}`,
				providerBootstrapCommand,
				captureClaude,
			),
			verify: func(root, path string) error {
				return verifyCommandHookJSON(root, path, "UserPromptSubmit", captureClaude, false)
			},
		},
		{
			name:     "Codex 29",
			relative: ".codex/hooks.json",
			contents: fmt.Sprintf(
				`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":%q,"commandWindows":%q,"timeout":15}]}],"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"commandWindows":%q,"timeout":29}]}]}}`,
				providerBootstrapCommand,
				providerBootstrapCommand,
				captureCodex,
				captureCodex,
			),
			verify: func(root, path string) error {
				return verifyCommandHookJSON(root, path, "UserPromptSubmit", captureCodex, true)
			},
		},
		{
			name:     "Copilot 31",
			relative: ".github/hooks/prompt-audit.json",
			contents: fmt.Sprintf(
				`{"version":1,"disableAllHooks":false,"hooks":{"SessionStart":[{"type":"command","command":%q,"cwd":".","timeout":15}],"UserPromptSubmit":[{"type":"command","command":%q,"cwd":".","timeout":31}]}}`,
				providerBootstrapCommand,
				captureCopilot,
			),
			verify: func(root, path string) error {
				return verifyCopilotHookJSON(root, path, captureCopilot, providerBootstrapCommand)
			},
		},
		{
			name:     "Claude bootstrap 14",
			relative: ".claude/settings.json",
			contents: fmt.Sprintf(
				`{"disableAllHooks":false,"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":%q,"timeout":14}]}],"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"timeout":30}]}]}}`,
				providerBootstrapCommand,
				captureClaude,
			),
			verify: func(root, path string) error {
				return verifyCommandHookJSON(root, path, "SessionStart", providerBootstrapCommand, false)
			},
		},
		{
			name:     "Codex bootstrap 16",
			relative: ".codex/hooks.json",
			contents: fmt.Sprintf(
				`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":%q,"commandWindows":%q,"timeout":16}]}],"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"commandWindows":%q,"timeout":30}]}]}}`,
				providerBootstrapCommand,
				providerBootstrapCommand,
				captureCodex,
				captureCodex,
			),
			verify: func(root, path string) error {
				return verifyCommandHookJSON(root, path, "SessionStart", providerBootstrapCommand, true)
			},
		},
		{
			name:     "Copilot bootstrap 14",
			relative: ".github/hooks/prompt-audit.json",
			contents: fmt.Sprintf(
				`{"version":1,"disableAllHooks":false,"hooks":{"SessionStart":[{"type":"command","command":%q,"cwd":".","timeout":14}],"UserPromptSubmit":[{"type":"command","command":%q,"cwd":".","timeout":30}]}}`,
				providerBootstrapCommand,
				captureCopilot,
			),
			verify: func(root, path string) error {
				return verifyCopilotHookJSON(root, path, captureCopilot, providerBootstrapCommand)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			path := writeProviderHardeningFixture(t, root, testCase.relative, testCase.contents)
			if err := testCase.verify(root, path); err == nil {
				t.Fatalf("%s hook accepted a noncanonical event timeout", testCase.name)
			}
		})
	}
}

func TestProviderHooksRejectExecutionChangingFields(t *testing.T) {
	captureClaude := providerCaptureCommand + model.ToolClaudeCode
	captureCopilot := providerCaptureCommand + model.ToolCopilotCLI
	for _, testCase := range []struct {
		name     string
		relative string
		contents string
		verify   func(string, string) error
	}{
		{
			name:     "Claude async",
			relative: ".claude/settings.json",
			contents: fmt.Sprintf(
				`{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"timeout":30,"async":true}]}]}}`,
				captureClaude,
			),
			verify: func(root, path string) error {
				return verifyCommandHookJSON(root, path, "UserPromptSubmit", captureClaude, false)
			},
		},
		{
			name:     "Claude args",
			relative: ".claude/settings.json",
			contents: fmt.Sprintf(
				`{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"timeout":30,"args":["--bypass"]}]}]}}`,
				captureClaude,
			),
			verify: func(root, path string) error {
				return verifyCommandHookJSON(root, path, "UserPromptSubmit", captureClaude, false)
			},
		},
		{
			name:     "Claude shell",
			relative: ".claude/settings.json",
			contents: fmt.Sprintf(
				`{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"timeout":30,"shell":true}]}]}}`,
				captureClaude,
			),
			verify: func(root, path string) error {
				return verifyCommandHookJSON(root, path, "UserPromptSubmit", captureClaude, false)
			},
		},
		{
			name:     "Copilot env",
			relative: ".github/hooks/prompt-audit.json",
			contents: fmt.Sprintf(
				`{"version":1,"disableAllHooks":false,"hooks":{"SessionStart":[{"type":"command","command":%q,"cwd":".","timeout":15}],"UserPromptSubmit":[{"type":"command","command":%q,"cwd":".","timeout":30,"env":{"PROMPT_AUDIT_REPOSITORY_ROOT":"elsewhere"}}]}}`,
				providerBootstrapCommand,
				captureCopilot,
			),
			verify: func(root, path string) error {
				return verifyCopilotHookJSON(root, path, captureCopilot, providerBootstrapCommand)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			path := writeProviderHardeningFixture(t, root, testCase.relative, testCase.contents)
			if err := testCase.verify(root, path); err == nil {
				t.Fatalf("%s hook accepted an execution-changing field", testCase.name)
			}
		})
	}
}

func TestProviderHooksRequireSessionBootstrap(t *testing.T) {
	captureClaude := providerCaptureCommand + model.ToolClaudeCode
	captureCodex := providerCaptureCommand + model.ToolCodex
	captureCopilot := providerCaptureCommand + model.ToolCopilotCLI
	for _, testCase := range []struct {
		name     string
		relative string
		contents string
		verify   func(string, string) error
	}{
		{
			name:     "Claude",
			relative: ".claude/settings.json",
			contents: fmt.Sprintf(
				`{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"timeout":30}]}]}}`,
				captureClaude,
			),
			verify: func(root, path string) error {
				return verifyCommandHookJSON(root, path, "SessionStart", providerBootstrapCommand, false)
			},
		},
		{
			name:     "Codex",
			relative: ".codex/hooks.json",
			contents: fmt.Sprintf(
				`{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"commandWindows":%q,"timeout":30}]}]}}`,
				captureCodex,
				captureCodex,
			),
			verify: func(root, path string) error {
				return verifyCommandHookJSON(root, path, "SessionStart", providerBootstrapCommand, true)
			},
		},
		{
			name:     "Copilot",
			relative: ".github/hooks/prompt-audit.json",
			contents: fmt.Sprintf(
				`{"version":1,"disableAllHooks":false,"hooks":{"UserPromptSubmit":[{"type":"command","command":%q,"cwd":".","timeout":30}]}}`,
				captureCopilot,
			),
			verify: func(root, path string) error {
				return verifyCopilotHookJSON(root, path, captureCopilot, providerBootstrapCommand)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			path := writeProviderHardeningFixture(t, root, testCase.relative, testCase.contents)
			if err := testCase.verify(root, path); err == nil {
				t.Fatalf("%s hook without session bootstrap was accepted", testCase.name)
			}
		})
	}
}

func TestProviderConfigRejectsSymlinkedParentDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeProviderHardeningFixture(
		t,
		outside,
		"config.toml",
		"project_doc_fallback_filenames = [\".codex/AGENTS.md\"]\n\n[features]\nhooks = true\n",
	)
	parent := filepath.Join(root, ".codex")
	if err := os.Symlink(outside, parent); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}
	if err := verifyCodexProjectConfig(root, filepath.Join(parent, "config.toml")); err == nil {
		t.Fatal("verifyCodexProjectConfig() followed a symlinked provider directory")
	}
}

func TestDisableAllHooksMustBeExplicitlyFalse(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		contents string
	}{
		{name: "missing", contents: `{}`},
		{name: "true", contents: `{"disableAllHooks":true}`},
		{name: "non-boolean", contents: `{"disableAllHooks":"false"}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			path := writeProviderHardeningFixture(
				t,
				root,
				".claude/settings.json",
				testCase.contents,
			)
			if err := verifyClaudeHooksEnabled(root, path, true); err == nil {
				t.Fatalf("verifyClaudeHooksEnabled() accepted %s disableAllHooks", testCase.name)
			}
		})
	}
}

func TestActivateRecordsAlteredCanonicalProviderWrappers(t *testing.T) {
	for _, relative := range []string{".devtools/setup", ".devtools/setup.cmd"} {
		t.Run(filepath.Base(relative), func(t *testing.T) {
			repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
			enableTestLocalStore(t, repository)
			useTestConfigDirectory(t)
			path := filepath.Join(repository.Root, filepath.FromSlash(relative))
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString("\nrem altered\n"); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}

			// A wrapper is executable code and is never rewritten from inside
			// the process it launched, so this is the one condition that stays
			// unrepaired. It must still not end the worker's session: the
			// degradation goes to the health log, where status and the company
			// can see it.
			var out bytes.Buffer
			if err := Activate(&out, repository.Root); err != nil {
				t.Fatalf("Activate() after altering %s = %v", relative, err)
			}
			repo, err := DiscoverRepository(repository.Root)
			if err != nil {
				t.Fatalf("discover repository: %v", err)
			}
			if err := verifyProviderCaptureConfiguration(repo); err == nil ||
				!strings.Contains(err.Error(), relative) {
				t.Fatalf("an altered %s must still be detected: %v", relative, err)
			}
			health, err := os.ReadFile(filepath.Join(localStoreDir(repository.Root), healthLogFileName))
			if err != nil {
				t.Fatalf("read health log: %v", err)
			}
			if !strings.Contains(string(health), "degraded") {
				t.Fatalf("the degradation must be recorded: %q", string(health))
			}
		})
	}
}

func TestCanonicalRecoverWrappersWaitForRecoveryCompletion(t *testing.T) {
	_, helperPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate canonical recovery wrappers")
	}
	devtoolsRoot := filepath.Clean(filepath.Join(filepath.Dir(helperPath), "..", "..", "..", ".."))
	for _, testCase := range []struct {
		name      string
		required  string
		forbidden []string
	}{
		{
			name:     "setup",
			required: `"$binary" "$@" >/dev/null 2>&1`,
			forbidden: []string{
				"sleep 12",
				`kill "$recover_pid"`,
			},
		},
		{
			name:     "setup.cmd",
			required: `"%ENV_BINARY%" recover >nul 2>&1`,
			forbidden: []string{
				"WaitForExit(12000)",
				"$process.Kill()",
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			contents, err := os.ReadFile(filepath.Join(devtoolsRoot, testCase.name))
			if err != nil {
				t.Fatalf("read canonical recovery wrapper: %v", err)
			}
			wrapper := string(contents)
			if !strings.Contains(wrapper, testCase.required) {
				t.Fatal("canonical recovery wrapper does not synchronously wait for the agent")
			}
			for _, forbidden := range testCase.forbidden {
				if strings.Contains(wrapper, forbidden) {
					t.Fatalf("canonical recovery wrapper can kill unfinished recovery via %q", forbidden)
				}
			}
		})
	}
}

func TestVerifyProviderConfigurationRepairsPOSIXWrapperMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX executable mode bits")
	}
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	path := filepath.Join(repository.Root, ".devtools", "setup")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() with canonical non-executable wrapper = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Fatal("Activate() did not restore the POSIX executable mode")
	}
}

func TestActivateRejectsSymlinkedProviderWrapper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks on Windows can require an elevated token")
	}
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	path := filepath.Join(repository.Root, ".devtools", "setup")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "canonical-setup")
	if err := os.WriteFile(target, contents, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err = Activate(&out, repository.Root)
	if err == nil || !strings.Contains(err.Error(), ".devtools/setup") {
		t.Fatalf("Activate() with symlinked canonical wrapper = %v, want fail-closed error", err)
	}
}

func TestActivateRepairsClaudeDisableAllHooksInProjectSettings(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	path := filepath.Join(repository.Root, ".claude", "settings.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	altered := bytes.Replace(contents, []byte(`"disableAllHooks":false`), []byte(`"disableAllHooks":true`), 1)
	if bytes.Equal(altered, contents) {
		t.Fatal("Claude fixture did not contain the canonical disableAllHooks setting")
	}
	if err := os.WriteFile(path, altered, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() with project disableAllHooks=true = %v", err)
	}
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatalf("discover repository: %v", err)
	}
	if err := verifyProviderCaptureConfiguration(repo); err != nil {
		t.Fatalf("disabled project hooks must be re-enabled: %v", err)
	}
}

func TestActivateRepairsClaudeLocalDisableAllHooks(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		contents  string
		wantError bool
	}{
		{name: "false", contents: `{"disableAllHooks":false}`},
		{name: "true", contents: `{"disableAllHooks":true}`, wantError: true},
		{name: "non-boolean", contents: `{"disableAllHooks":"false"}`, wantError: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
			enableTestLocalStore(t, repository)
			useTestConfigDirectory(t)
			path := filepath.Join(repository.Root, ".claude", "settings.local.json")
			if err := os.WriteFile(path, []byte(testCase.contents), 0o600); err != nil {
				t.Fatal(err)
			}

			var out bytes.Buffer
			err := Activate(&out, repository.Root)
			if testCase.wantError {
				// The worker owns this file, so the switch is corrected by a
				// merge that keeps their other settings.
				if err != nil {
					t.Fatalf("Activate() with local settings %s = %v", testCase.name, err)
				}
				repo, discoverErr := DiscoverRepository(repository.Root)
				if discoverErr != nil {
					t.Fatalf("discover repository: %v", discoverErr)
				}
				if verifyErr := verifyProviderCaptureConfiguration(repo); verifyErr != nil {
					t.Fatalf("local disableAllHooks must be repaired: %v", verifyErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Activate() with local disableAllHooks=false = %v", err)
			}
		})
	}
}

// Activation repairs an altered Copilot hook file instead of ending the
// session. Refusing to continue never restored capture; it only stopped the
// worker, and prompts kept being lost until somebody investigated.
func TestActivateRepairsInvalidCopilotHookVersion(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCopilotCLI})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	path := filepath.Join(repository.Root, ".github", "hooks", "prompt-audit.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	altered := bytes.Replace(contents, []byte(`"version":1`), []byte(`"version":2`), 1)
	if bytes.Equal(altered, contents) {
		t.Fatal("Copilot fixture did not contain version 1")
	}
	if err := os.WriteFile(path, altered, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() must not end the session over an altered hook file: %v", err)
	}
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatalf("discover repository: %v", err)
	}
	if err := verifyProviderCaptureConfiguration(repo); err != nil {
		t.Fatalf("the Copilot hook file must be canonical after activation: %v", err)
	}
}

func TestActivateRepairsCopilotDisableAllHooks(t *testing.T) {
	tests := []struct {
		name     string
		relative string
	}{
		{name: "hook file", relative: ".github/hooks/prompt-audit.json"},
		{name: "project settings", relative: ".github/copilot/settings.json"},
		{name: "local settings", relative: ".github/copilot/settings.local.json"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCopilotCLI})
			enableTestLocalStore(t, repository)
			useTestConfigDirectory(t)
			path := filepath.Join(repository.Root, filepath.FromSlash(testCase.relative))
			if strings.Contains(testCase.relative, "hooks/") {
				contents, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				contents = bytes.Replace(
					contents,
					[]byte(`"disableAllHooks":false`),
					[]byte(`"disableAllHooks":true`),
					1,
				)
				if err := os.WriteFile(path, contents, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte(`{"disableAllHooks":true}`), 0o600); err != nil {
				t.Fatal(err)
			}

			var out bytes.Buffer
			if err := Activate(&out, repository.Root); err != nil {
				t.Fatalf("Activate() must not end the session over disableAllHooks: %v", err)
			}
			repo, err := DiscoverRepository(repository.Root)
			if err != nil {
				t.Fatalf("discover repository: %v", err)
			}
			if err := verifyProviderCaptureConfiguration(repo); err != nil {
				t.Fatalf("disableAllHooks must be repaired in %s: %v", testCase.relative, err)
			}
		})
	}
}

// Neither an extra hook file nor a worker's own hooks can remove ours, so
// neither may interrupt the session. Blocking on them meant a .DS_Store was
// enough to stop every employee from working.
func TestActivateToleratesAdditionalCopilotHookSources(t *testing.T) {
	t.Run("extra hook file", func(t *testing.T) {
		repository := newTestRepository(t, "http://localhost:8080", nil)
		enableTestLocalStore(t, repository)
		useTestConfigDirectory(t)
		path := filepath.Join(repository.Root, ".github", "hooks", "team-hook.json")
		if err := os.WriteFile(
			path,
			[]byte(`{"version":1,"hooks":{"SessionStart":[{"type":"command","command":"echo hola"}]}}`),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Activate(&out, repository.Root); err != nil {
			t.Fatalf("Activate() with an extra Copilot hook file = %v", err)
		}
	})

	t.Run("worker local hooks", func(t *testing.T) {
		repository := newTestRepository(t, "http://localhost:8080", nil)
		enableTestLocalStore(t, repository)
		useTestConfigDirectory(t)
		path := filepath.Join(repository.Root, ".github", "copilot", "settings.local.json")
		if err := os.WriteFile(
			path,
			[]byte(`{"disableAllHooks":false,"hooks":{"Stop":[]}}`),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Activate(&out, repository.Root); err != nil {
			t.Fatalf("Activate() with worker-owned local hooks = %v", err)
		}
	})
}

func TestActivateRepairsDisabledVSCodeCopilotHookLocation(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", nil)
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	path := filepath.Join(repository.Root, ".vscode", "settings.json")
	if err := os.WriteFile(
		path,
		[]byte(`{"chat.hookFilesLocations":{".github/hooks":false}}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() must not end the session over VS Code settings: %v", err)
	}
	if err := verifyVSCodeHookLocations(repository.Root, path); err != nil {
		t.Fatalf("VS Code hook discovery must be repaired: %v", err)
	}
}

// Settings that cannot be parsed are left alone: rewriting them would destroy
// worker content we cannot round-trip. The session still continues, and the
// degradation is recorded rather than thrown at the worker.
func TestActivateLeavesUnparseableVSCodeSettingsAlone(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", nil)
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	path := filepath.Join(repository.Root, ".vscode", "settings.json")
	original := []byte(`{"chat.hookFilesLocations":{".github/hooks":true,".claude/settings.json":false,".claude/settings.local.json":false,"~/.claude/settings.json":false}} {}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() with unparseable VS Code settings = %v", err)
	}
	preserved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preserved, original) {
		t.Fatal("unparseable worker settings must not be rewritten")
	}
}

func TestProviderHookVerifierRejectsResponseEvent(t *testing.T) {
	root := t.TempDir()
	capture := providerCaptureCommand + model.ToolClaudeCode
	contents := fmt.Sprintf(
		`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":%q,"timeout":15}]}],"UserPromptSubmit":[{"hooks":[{"type":"command","command":%q,"timeout":30}]}],"Stop":[{"hooks":[{"type":"command","command":"echo forbidden","timeout":30}]}]}}`,
		providerBootstrapCommand,
		capture,
	)
	path := writeProviderHardeningFixture(t, root, ".claude/settings.json", contents)
	if err := verifyCommandHookJSON(root, path, "UserPromptSubmit", capture, false); err == nil {
		t.Fatal("provider hook verifier accepted an assistant/stop event")
	}
}

func TestProviderHookVerifierRejectsDuplicateHookKeys(t *testing.T) {
	root := t.TempDir()
	path := writeProviderHardeningFixture(
		t,
		root,
		".github/hooks/prompt-audit.json",
		`{"version":1,"disableAllHooks":false,"hooks":{"SessionStart":[]},"hooks":{"UserPromptSubmit":[]}}`,
	)
	if err := verifyCopilotHookJSON(
		root,
		path,
		providerCaptureCommand+model.ToolCopilotCLI,
		providerBootstrapCommand,
	); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("verifyCopilotHookJSON() with duplicate hooks = %v", err)
	}
}

func TestCentralActivatePreparesAutoEnrollmentWithoutPreCommit(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	useTestConfigDirectory(t)
	project := setTestProjectAutoEnroll(t, repository, true)

	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() in central auto-enrollment mode = %v", err)
	}
	cfg, profile, err := loadUserConfigForProject(project)
	if err != nil {
		t.Fatalf("load central capture profile after Activate(): %v", err)
	}
	if profile == "" || cfg.UserID == "" || cfg.Token == "" {
		t.Fatal("Activate() did not prepare a durable central capture profile")
	}
	hookPath := filepath.Join(repository.Root, ".git", "hooks", "pre-commit")
	if _, err := os.Lstat(hookPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("central Activate() installed a pre-commit hook: %v", err)
	}
}

func TestCentralActivateRequiresManualConfiguration(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	useTestConfigDirectory(t)

	var out bytes.Buffer
	err := Activate(&out, repository.Root)
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Activate() in unconfigured central manual mode = %v, want ErrNotConfigured", err)
	}
}

func TestCentralInitPreparesCaptureWithoutPreCommit(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	useTestConfigDirectory(t)
	setTestProjectAutoEnroll(t, repository, true)

	var out bytes.Buffer
	if err := Init(&out, repository.Root); err != nil {
		t.Fatalf("Init() in central mode = %v", err)
	}
	hookPath := filepath.Join(repository.Root, ".git", "hooks", "pre-commit")
	if _, err := os.Lstat(hookPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("central Init() installed a pre-commit hook: %v", err)
	}
}

func TestEnsurePreCommitHookRepairsCanonicalModeAndRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX executable mode bits")
	}
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	hookPath := filepath.Join(repository.Root, ".git", "hooks", "pre-commit")
	if err := ensurePreCommitHook(repository.Root); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hookPath, 0o655); err != nil {
		t.Fatal(err)
	}
	if err := ensurePreCommitHook(repository.Root); err != nil {
		t.Fatalf("repair canonical pre-commit mode: %v", err)
	}
	info, err := os.Lstat(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Fatal("canonical pre-commit hook remained non-executable")
	}

	if err := os.Remove(hookPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside-hook")
	if err := os.WriteFile(target, []byte(preCommitHookScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, hookPath); err != nil {
		t.Fatal(err)
	}
	if err := ensurePreCommitHook(repository.Root); err == nil {
		t.Fatal("ensurePreCommitHook accepted a symlink")
	}
}
