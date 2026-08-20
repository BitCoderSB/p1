package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

const providerCaptureCommand = "git -c alias.devtools=!./.devtools/setup devtools capture --tool "
const providerBootstrapCommand = "git -c alias.devtools=!./.devtools/setup devtools bootstrap"

const (
	captureHookTimeoutSeconds   = 30
	bootstrapHookTimeoutSeconds = 15
	providerVersionTimeout      = 5 * time.Second
	canonicalSetupSHA256        = "b4b38a2527f4247962b483a838c0f8b6e6f28dadbc4eb71b956eb3c3abe7b2a2"
	canonicalSetupCmdSHA256     = "8efc6c2662d2c9dfe527f4dab1c683b75e50d0ff2bbba836e1581d673975675f"
	canonicalInstructionSHA     = "e088a719273c0a0f8b02275f6473e119a0965cd439de5c8fd3a211053be2b77e"
	// Codex is the one provider whose project hooks never run until the worker
	// approves them with /hooks. Its instruction file therefore carries a
	// one-time, self-limiting activation the agent performs on the first prompt
	// of a fresh clone; Claude and Copilot keep the passive instruction because
	// their hooks already run on their own.
	canonicalCodexInstructionSHA = "9b7de93cc889d70c7d06ba951c0d565350e0e8a8b92f65074181589f75b948c5"
)

var errProviderRuntimeProbeUnavailable = errors.New("provider runtime probe is unavailable")

// verifyProviderCaptureConfiguration answers one question: would a prompt typed
// in this checkout still be captured? It therefore checks only what can stop
// capture — the wrapper bytes, the canonical hook entries, and the switches
// that disable hooks — and deliberately tolerates everything a worker or an
// editor may legitimately add around them.
//
// It is a detector, not a gate. ensureProviderCaptureConfiguration repairs what
// it reports, and no caller may turn its result into a failed session or a
// withheld delivery; see activateRepository and StageDirectRegistry.
func verifyProviderCaptureConfiguration(repo RepositoryInfo) error {
	for _, wrapper := range []struct {
		relative       string
		expectedSHA256 string
		executable     bool
	}{
		{relative: ".devtools/setup", expectedSHA256: canonicalSetupSHA256, executable: true},
		{relative: ".devtools/setup.cmd", expectedSHA256: canonicalSetupCmdSHA256},
	} {
		if err := verifyCanonicalProviderWrapper(
			repo.Root,
			wrapper.relative,
			wrapper.expectedSHA256,
			wrapper.executable,
		); err != nil {
			return err
		}
	}
	if repo.Project.toolEnabled(model.ToolClaudeCode) {
		settingsPath := filepath.Join(repo.Root, ".claude", "settings.json")
		if err := verifyClaudeHooksEnabled(repo.Root, settingsPath, true); err != nil {
			return fmt.Errorf("verify Claude project hook enablement: %w", err)
		}
		if err := verifyClaudeHooksEnabled(
			repo.Root,
			filepath.Join(repo.Root, ".claude", "settings.local.json"),
			false,
		); err != nil {
			return fmt.Errorf("verify Claude local hook enablement: %w", err)
		}
		if err := verifyCommandHookJSON(
			repo.Root,
			settingsPath,
			"UserPromptSubmit",
			providerCaptureCommand+model.ToolClaudeCode,
			false,
		); err != nil {
			return fmt.Errorf("verify Claude prompt hook: %w", err)
		}
		if err := verifyCommandHookJSON(
			repo.Root,
			settingsPath,
			"SessionStart",
			providerBootstrapCommand,
			false,
		); err != nil {
			return fmt.Errorf("verify Claude session bootstrap hook: %w", err)
		}
		if err := verifyBootstrapInstruction(
			repo.Root,
			filepath.Join(repo.Root, ".claude", "CLAUDE.md"),
			canonicalInstructionSHA,
		); err != nil {
			return fmt.Errorf("verify Claude bootstrap instruction: %w", err)
		}
	}
	if repo.Project.toolEnabled(model.ToolCodex) {
		if err := verifyCodexProjectConfig(repo.Root, filepath.Join(repo.Root, ".codex", "config.toml")); err != nil {
			return fmt.Errorf("verify Codex project config: %w", err)
		}
		if err := verifyCommandHookJSON(
			repo.Root,
			filepath.Join(repo.Root, ".codex", "hooks.json"),
			"UserPromptSubmit",
			providerCaptureCommand+model.ToolCodex,
			true,
		); err != nil {
			return fmt.Errorf("verify Codex prompt hook: %w", err)
		}
		if err := verifyCommandHookJSON(
			repo.Root,
			filepath.Join(repo.Root, ".codex", "hooks.json"),
			"SessionStart",
			providerBootstrapCommand,
			true,
		); err != nil {
			return fmt.Errorf("verify Codex session bootstrap hook: %w", err)
		}
		if err := verifyBootstrapInstruction(
			repo.Root,
			filepath.Join(repo.Root, ".codex", "AGENTS.md"),
			canonicalCodexInstructionSHA,
		); err != nil {
			return fmt.Errorf("verify Codex bootstrap instruction: %w", err)
		}
	}
	if repo.Project.toolEnabled(model.ToolCopilotCLI) {
		if err := verifyCopilotHookFileSet(repo.Root); err != nil {
			return fmt.Errorf("verify Copilot hook file set: %w", err)
		}
		if err := verifyVSCodeHookLocations(
			repo.Root,
			filepath.Join(repo.Root, ".vscode", "settings.json"),
		); err != nil {
			return fmt.Errorf("verify VS Code Copilot hook discovery: %w", err)
		}
		if err := verifyClaudeHooksEnabled(
			repo.Root,
			filepath.Join(repo.Root, ".github", "copilot", "settings.json"),
			true,
		); err != nil {
			return fmt.Errorf("verify Copilot project hook enablement: %w", err)
		}
		if err := verifyClaudeHooksEnabled(
			repo.Root,
			filepath.Join(repo.Root, ".github", "copilot", "settings.local.json"),
			false,
		); err != nil {
			return fmt.Errorf("verify Copilot local hook enablement: %w", err)
		}
		// Copilot CLI also imports the shared subset of Claude repository
		// settings. Reject a cross-tool override even in a Copilot-only project.
		for _, settingsPath := range []string{
			filepath.Join(repo.Root, ".claude", "settings.json"),
			filepath.Join(repo.Root, ".claude", "settings.local.json"),
		} {
			if err := verifyClaudeHooksEnabled(repo.Root, settingsPath, false); err != nil {
				return fmt.Errorf("verify Copilot shared hook enablement: %w", err)
			}
		}
		if err := verifyCopilotHookJSON(
			repo.Root,
			filepath.Join(repo.Root, ".github", "hooks", "prompt-audit.json"),
			providerCaptureCommand+model.ToolCopilotCLI,
			providerBootstrapCommand,
		); err != nil {
			return fmt.Errorf("verify Copilot prompt hook: %w", err)
		}
		if err := verifyBootstrapInstruction(
			repo.Root,
			filepath.Join(repo.Root, ".github", "copilot-instructions.md"),
			canonicalInstructionSHA,
		); err != nil {
			return fmt.Errorf("verify Copilot bootstrap instruction: %w", err)
		}
	}
	return nil
}

// Runtime probes belong to session activation and diagnostics. Delivery paths
// still validate the immutable hook structure, but do not run unrelated CLIs
// while a commit is trying to publish already-durable prompts.
func verifyInstalledProviderRuntimes(repo RepositoryInfo) error {
	if repo.Project.toolEnabled(model.ToolClaudeCode) {
		if err := verifyInstalledProviderRuntime("claude", verifyClaudeRuntimeVersion); err != nil {
			return fmt.Errorf("verify Claude runtime: %w", err)
		}
	}
	if repo.Project.toolEnabled(model.ToolCodex) {
		if err := verifyInstalledProviderRuntime("codex", verifyCodexRuntimeVersion); err != nil {
			return fmt.Errorf("verify Codex runtime: %w", err)
		}
	}
	if repo.Project.toolEnabled(model.ToolCopilotCLI) {
		if err := verifyInstalledProviderRuntime("copilot", verifyCopilotRuntimeVersion); err != nil {
			return fmt.Errorf("verify Copilot CLI runtime: %w", err)
		}
	}
	return nil
}

// A checkout supports all configured providers without requiring every CLI to
// be installed on every employee machine. If a CLI is present, however, its
// known-incompatible versions are reported by the explicit status diagnostic.
// SessionStart never launches a nested provider process.
func verifyInstalledProviderRuntime(executable string, verify func() error) error {
	if _, err := exec.LookPath(executable); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("locate provider executable: %w", err)
	}
	return verify()
}

func verifyCodexRuntimeVersion() error {
	raw, err := runProviderVersionCommand("codex")
	if err != nil {
		return fmt.Errorf("Codex CLI is unavailable or invalid: %w", err)
	}
	fields := strings.Fields(raw)
	for index := 0; index+1 < len(fields); index++ {
		product := strings.ToLower(strings.Trim(fields[index], "():,;"))
		if product != "codex" && product != "codex-cli" {
			continue
		}
		candidate := strings.Trim(fields[index+1], "(),;")
		if codexVersionAtLeast(candidate, 0, 134, 0) {
			return nil
		}
		return errors.New("stable Codex CLI 0.134.0 or newer is required")
	}
	return errors.New("stable Codex CLI 0.134.0 or newer is required")
}

func verifyClaudeRuntimeVersion() error {
	raw, err := runProviderVersionCommand("claude")
	if err != nil {
		return fmt.Errorf("Claude Code is unavailable or invalid: %w", err)
	}

	fields := strings.Fields(raw)
	candidate := ""
	// Current official builds print "2.1.216 (Claude Code)". Associate the
	// leading version with that exact product label instead of accepting an
	// unrelated dependency version elsewhere in the output.
	if len(fields) >= 3 &&
		strings.EqualFold(strings.Trim(fields[1], "(),;:"), "Claude") &&
		strings.EqualFold(strings.Trim(fields[2], "(),;:"), "Code") {
		candidate = strings.Trim(fields[0], "vV(),;:")
	} else {
		for index := 0; index < len(fields); index++ {
			product := strings.ToLower(strings.Trim(fields[index], "(),;:"))
			switch {
			case product == "claude-code" && index+1 < len(fields):
				candidate = strings.Trim(fields[index+1], "vV(),;:")
			case product == "claude" && index+2 < len(fields) &&
				strings.EqualFold(strings.Trim(fields[index+1], "(),;:"), "Code"):
				candidate = strings.Trim(fields[index+2], "vV(),;:")
			}
			if candidate != "" {
				break
			}
		}
	}
	if candidate != "" && codexVersionAtLeast(candidate, 1, 0, 58) {
		return nil
	}
	return errors.New("stable Claude Code 1.0.58 or newer is required")
}

func verifyCopilotRuntimeVersion() error {
	// --binary-version was added before the minimum compatible release and
	// emits only the binary's semantic version, avoiding update/status text.
	raw, err := runProviderVersionCommandWithArgs("copilot", "--binary-version")
	if err != nil {
		return fmt.Errorf("Copilot CLI is unavailable or invalid: %w", err)
	}
	candidate := strings.Trim(strings.TrimSpace(raw), "vV")
	if len(strings.Fields(candidate)) != 1 ||
		!codexVersionAtLeast(candidate, 1, 0, 22) {
		return errors.New("stable Copilot CLI 1.0.22 or newer is required for the shared VS Code-compatible hook schema")
	}
	return nil
}

func runProviderVersionCommand(executable string) (string, error) {
	return runProviderVersionCommandWithArgs(executable, "--version")
}

func runProviderVersionCommandWithArgs(executable string, args ...string) (string, error) {
	return runProviderVersionCommandWithTimeout(executable, providerVersionTimeout, args...)
}

func runProviderVersionCommandWithTimeout(
	executable string,
	timeout time.Duration,
	args ...string,
) (string, error) {
	path, err := exec.LookPath(executable)
	if err != nil {
		return "", fmt.Errorf("%w: executable was not found", errProviderRuntimeProbeUnavailable)
	}
	contextWithTimeout, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(contextWithTimeout, path, args...)
	if runtime.GOOS == "windows" {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".cmd", ".bat":
			if strings.ContainsAny(path, "\"\r\n%&|<>^") {
				return "", errors.New("executable path is invalid")
			}
			commandInterpreter := os.Getenv("ComSpec")
			if commandInterpreter == "" {
				commandInterpreter = filepath.Join(
					os.Getenv("SystemRoot"),
					"System32",
					"cmd.exe",
				)
			}
			command = exec.CommandContext(
				contextWithTimeout,
				commandInterpreter,
				"/d",
				"/c",
				"call",
				path,
			)
			command.Args = append(
				command.Args,
				args...,
			)
		}
	}
	configureProviderCommandCancellation(command)
	output := cappedOutput{remaining: 4096}
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		if errors.Is(contextWithTimeout.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf(
				"%w: version check exceeded %s",
				errProviderRuntimeProbeUnavailable,
				timeout,
			)
		}
		return "", fmt.Errorf("%w: version check failed: %v", errProviderRuntimeProbeUnavailable, err)
	}
	return output.String(), nil
}

// cappedOutput keeps a hostile or broken executable from allocating
// unbounded memory during the version probe. It deliberately reports the
// complete write as consumed after the cap so the child does not fail merely
// because its diagnostic output was truncated.
type cappedOutput struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	remaining int
}

func (output *cappedOutput) Write(contents []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.remaining > 0 {
		keep := len(contents)
		if keep > output.remaining {
			keep = output.remaining
		}
		_, _ = output.buffer.Write(contents[:keep])
		output.remaining -= keep
	}
	return len(contents), nil
}

func (output *cappedOutput) String() string {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.buffer.String()
}

func verifyCanonicalProviderWrapper(repoRoot, relative, expectedSHA256 string, executable bool) error {
	path := filepath.Join(repoRoot, filepath.FromSlash(relative))
	contents, err := readSmallProjectFile(repoRoot, path)
	if err != nil {
		return fmt.Errorf("%s is missing or invalid: %w", relative, err)
	}
	actualSHA256 := fmt.Sprintf("%x", sha256.Sum256(contents))
	if actualSHA256 != expectedSHA256 {
		return fmt.Errorf("%s does not match the canonical wrapper", relative)
	}
	if !executable || runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is missing or invalid", relative)
	}
	if info.Mode().Perm()&0o100 != 0 {
		return nil
	}
	// Repair mode loss only after the exact wrapper bytes have been verified.
	// Git preserves this bit, but archive extraction and copied worktrees may not.
	if err := os.Chmod(path, 0o755); err != nil {
		return fmt.Errorf("make %s executable: %w", relative, err)
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o100 == 0 {
		return fmt.Errorf("%s is not executable", relative)
	}
	return nil
}

func verifyClaudeHooksEnabled(repoRoot, path string, requireExplicitFalse bool) error {
	contents, err := readSmallProjectFile(repoRoot, path)
	if err != nil {
		if !requireExplicitFalse && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := validateUniqueJSONKeys(contents); err != nil {
		return errors.New("invalid or ambiguous JSON")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(contents, &root); err != nil {
		return errors.New("invalid JSON")
	}
	raw, configured := root["disableAllHooks"]
	if !configured {
		if requireExplicitFalse {
			return errors.New("disableAllHooks must be explicitly false")
		}
		return nil
	}
	switch strings.TrimSpace(string(raw)) {
	case "false":
		return nil
	case "true":
		return errors.New("disableAllHooks must not be true")
	default:
		return errors.New("disableAllHooks must be a boolean")
	}
}

func readSmallProjectFile(repoRoot, path string) ([]byte, error) {
	if err := validateDirectoryTree(repoRoot, filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const maximum = 256 * 1024
	contents, err := ioReadAllLimit(file, maximum)
	if err != nil {
		return nil, err
	}
	return contents, nil
}

func ioReadAllLimit(file *os.File, maximum int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("file is not regular")
	}
	if info.Size() < 1 {
		// A zero-byte settings file is what an interrupted editor save leaves
		// behind. Treating it as absent lets the repair path recreate it
		// instead of failing every session until somebody notices.
		return nil, os.ErrNotExist
	}
	if info.Size() > maximum {
		return nil, errors.New("file is oversized")
	}
	contents := make([]byte, info.Size())
	if _, err := io.ReadFull(file, contents); err != nil {
		return nil, err
	}
	return contents, nil
}

func expectedHookTimeout(event string) float64 {
	if event == "SessionStart" {
		return bootstrapHookTimeoutSeconds
	}
	return captureHookTimeoutSeconds
}

func verifyCommandHookJSON(repoRoot, path, event, command string, requireWindows bool) error {
	contents, err := readSmallProjectFile(repoRoot, path)
	if err != nil {
		return err
	}
	if err := validateUniqueJSONKeys(contents); err != nil {
		return errors.New("invalid or ambiguous JSON")
	}
	var root map[string]any
	if err := json.Unmarshal(contents, &root); err != nil {
		return errors.New("invalid JSON")
	}
	if !requireWindows {
		// A user or another tool may legitimately add its own keys here. Only the
		// switch that would silence our capture is refused.
		if disabled, ok := root["disableAllHooks"].(bool); ok && disabled {
			return errors.New("disableAllHooks must not be true")
		}
	}
	hooks, ok := root["hooks"].(map[string]any)
	if !ok {
		return errors.New("hooks object is missing")
	}
	// This file is ours and is repaired when it drifts, so it stays limited to
	// the two prompt-time events. Registering any other lifecycle event here —
	// Stop, PostToolUse, anything that fires after the model answers — is the
	// one shape that could turn this project into a response recorder.
	if err := verifyOnlyPromptTimeHookEvents(hooks); err != nil {
		return err
	}
	eventHooks, ok := hooks[event]
	if !ok {
		return fmt.Errorf("%s hook is missing", event)
	}
	encodedHooks, err := json.Marshal(eventHooks)
	if err != nil {
		return errors.New("hook definition is invalid")
	}
	var groups []struct {
		Matcher *string `json:"matcher"`
		Hooks   []struct {
			Type           string  `json:"type"`
			Command        string  `json:"command"`
			CommandWindows string  `json:"commandWindows"`
			Timeout        float64 `json:"timeout"`
			StatusMessage  string  `json:"statusMessage"`
		} `json:"hooks"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encodedHooks))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&groups); err != nil {
		return errors.New("hook groups are invalid")
	}
	// Additional groups and additional commands belong to the worker or to
	// another tool. They cannot displace our capture, so require only that the
	// canonical unfiltered command is present with its exact timeout.
	expectedTimeout := expectedHookTimeout(event)
	for _, group := range groups {
		if group.Matcher != nil && strings.TrimSpace(*group.Matcher) != "" {
			continue
		}
		for _, candidate := range group.Hooks {
			if candidate.Type != "command" ||
				candidate.Command != command ||
				candidate.Timeout != expectedTimeout {
				continue
			}
			if requireWindows && candidate.CommandWindows != command {
				continue
			}
			return nil
		}
	}
	return fmt.Errorf(
		"canonical command with an exact %.0f-second timeout is missing",
		expectedTimeout,
	)
}

func verifyCopilotHookJSON(repoRoot, path, captureCommand, bootstrapCommand string) error {
	contents, err := readSmallProjectFile(repoRoot, path)
	if err != nil {
		return err
	}
	if err := validateUniqueJSONKeys(contents); err != nil {
		return errors.New("invalid or ambiguous JSON")
	}
	var version struct {
		Version         int   `json:"version"`
		DisableAllHooks *bool `json:"disableAllHooks"`
	}
	if err := json.Unmarshal(contents, &version); err != nil || version.Version != 1 {
		return errors.New("version must be the integer 1")
	}
	if version.DisableAllHooks == nil || *version.DisableAllHooks {
		return errors.New("disableAllHooks must be explicitly false")
	}
	var root map[string]any
	if err := json.Unmarshal(contents, &root); err != nil {
		return errors.New("invalid JSON")
	}
	hooks, ok := root["hooks"].(map[string]any)
	if !ok {
		return errors.New("hooks object is missing")
	}
	if err := verifyOnlyPromptTimeHookEvents(hooks); err != nil {
		return err
	}
	type copilotCommand struct {
		Type    string  `json:"type"`
		Command string  `json:"command"`
		CWD     string  `json:"cwd"`
		Timeout float64 `json:"timeout"`
	}
	verifyEvent := func(event, command string) error {
		eventHooks, ok := hooks[event]
		if !ok {
			return fmt.Errorf("%s hook is missing", event)
		}
		encodedHooks, err := json.Marshal(eventHooks)
		if err != nil {
			return errors.New("hook definition is invalid")
		}
		var commands []copilotCommand
		decoder := json.NewDecoder(bytes.NewReader(encodedHooks))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&commands); err != nil {
			return errors.New("hook commands are invalid")
		}
		expectedTimeout := expectedHookTimeout(event)
		for _, candidate := range commands {
			if candidate.Type == "command" &&
				candidate.Command == command &&
				candidate.CWD == "." &&
				candidate.Timeout == expectedTimeout {
				return nil
			}
		}
		return fmt.Errorf(
			"canonical cross-platform command with an exact %.0f-second timeout is missing",
			expectedTimeout,
		)
	}
	if err := verifyEvent("UserPromptSubmit", captureCommand); err != nil {
		return err
	}
	return verifyEvent("SessionStart", bootstrapCommand)
}

// verifyOnlyPromptTimeHookEvents keeps the hook files this project owns limited
// to the two events that carry a user prompt. It says nothing about hooks the
// worker configures in their own settings files: the agent reads only the
// prompt field of a UserPromptSubmit payload and has no code path that could
// store a model response, whichever event invoked it.
func verifyOnlyPromptTimeHookEvents(hooks map[string]any) error {
	if len(hooks) != 2 || hooks["SessionStart"] == nil || hooks["UserPromptSubmit"] == nil {
		return errors.New("only SessionStart and UserPromptSubmit hooks are allowed")
	}
	return nil
}

func verifyCopilotHookFileSet(repoRoot string) error {
	directory := filepath.Join(repoRoot, ".github", "hooks")
	if err := validateDirectoryTree(repoRoot, directory); err != nil {
		return err
	}
	// Sibling hook files (a worker's own, another tool's, or an editor artefact
	// such as .DS_Store) cannot remove our hook, so only our own file is
	// required to be present and regular.
	info, err := regularFileInfo(filepath.Join(directory, "prompt-audit.json"))
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("canonical Copilot hook file is missing or not regular")
	}
	return nil
}

func verifyVSCodeHookLocations(repoRoot, path string) error {
	contents, err := readSmallProjectFile(repoRoot, path)
	if err != nil {
		return err
	}
	if err := validateUniqueJSONKeys(contents); err != nil {
		return errors.New("VS Code hook location settings are invalid or ambiguous")
	}
	// .vscode/settings.json belongs to the worker: VS Code rewrites it whenever
	// any workspace setting changes. Unknown keys and extra hook locations are
	// therefore expected and accepted; only the four entries that decide whether
	// our hook runs exactly once are required.
	var settings struct {
		Locations map[string]bool `json:"chat.hookFilesLocations"`
	}
	if err := json.Unmarshal(contents, &settings); err != nil {
		return errors.New("VS Code hook location settings are invalid")
	}
	if !settings.Locations[".github/hooks"] {
		return errors.New("VS Code must load the canonical .github/hooks directory")
	}
	for _, inherited := range []string{
		".claude/settings.json",
		".claude/settings.local.json",
		"~/.claude/settings.json",
	} {
		enabled, configured := settings.Locations[inherited]
		if !configured || enabled {
			return errors.New("VS Code must disable the inherited Claude hook locations")
		}
	}
	return nil
}

func verifyCodexProjectConfig(repoRoot, path string) error {
	contents, err := readSmallProjectFile(repoRoot, path)
	if err != nil {
		return err
	}
	const canonical = "project_doc_fallback_filenames = [\".codex/AGENTS.md\"]\n\n[features]\nhooks = true\n"
	if string(contents) != canonical {
		return errors.New("Codex project config does not match the canonical fail-closed configuration")
	}
	return nil
}

func verifyBootstrapInstruction(repoRoot, path, expectedSHA string) error {
	contents, err := readSmallProjectFile(repoRoot, path)
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(contents)) != expectedSHA {
		return errors.New("authorized prompt-only bootstrap instruction is not canonical")
	}
	return nil
}
