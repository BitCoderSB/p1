package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

func discoverTestRepository(t *testing.T, repository testRepository) RepositoryInfo {
	t.Helper()
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatalf("discover repository: %v", err)
	}
	return repo
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// A worker's own workspace settings, extra hook files and personal hooks are
// ordinary. None of them can silence our capture, so none of them may make the
// session-start verification fail.
func TestVerificationToleratesOrdinaryWorkerConfiguration(t *testing.T) {
	useTestConfigDirectory(t)
	repository := newTestRepository(t, "https://audit.example.invalid", nil)
	enableTestLocalStore(t, repository)
	repo := discoverTestRepository(t, repository)

	if err := verifyProviderCaptureConfiguration(repo); err != nil {
		t.Fatalf("canonical fixture must verify: %v", err)
	}

	for _, scenario := range []struct {
		name  string
		apply func()
	}{
		{
			name: "VS Code writes an unrelated workspace setting",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".vscode", "settings.json"),
					`{"chat.hookFilesLocations":{".github/hooks":true,".claude/settings.json":false,`+
						`".claude/settings.local.json":false,"~/.claude/settings.json":false},`+
						`"editor.formatOnSave":true,"python.defaultInterpreterPath":"/usr/bin/python3"}`)
			},
		},
		{
			name: "VS Code adds another hook location",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".vscode", "settings.json"),
					`{"chat.hookFilesLocations":{".github/hooks":true,".claude/settings.json":false,`+
						`".claude/settings.local.json":false,"~/.claude/settings.json":false,`+
						`".team/hooks":true}}`)
			},
		},
		{
			name: "an OS metadata file lands in .github/hooks",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".github", "hooks", ".DS_Store"), "\x00\x01")
			},
		},
		{
			name: "the team adds its own Copilot hook file",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".github", "hooks", "team.json"),
					`{"version":1,"hooks":{}}`)
			},
		},
		{
			name: "the worker approves a Claude permission",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".claude", "settings.local.json"),
					`{"permissions":{"allow":["Bash(npm test)"]}}`)
			},
		},
		{
			name: "the worker configures a personal Claude hook",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".claude", "settings.local.json"),
					`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo done"}]}]}}`)
			},
		},
		{
			name: "the worker adds a model and env block to the project settings",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".claude", "settings.json"),
					`{"disableAllHooks":false,"model":"opus","env":{"FOO":"bar"},"hooks":{`+
						`"SessionStart":[{"hooks":[{"type":"command","command":"`+providerBootstrapCommand+`","timeout":15}]}],`+
						`"UserPromptSubmit":[{"hooks":[{"type":"command","command":"`+providerCaptureCommand+model.ToolClaudeCode+`","timeout":30},{"type":"command","command":"echo extra","timeout":30}]}]}}`)
			},
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			writeTestProviderFiles(t, repository.Root, repo.Project.EnabledTools)
			scenario.apply()
			if err := verifyProviderCaptureConfiguration(repo); err != nil {
				t.Fatalf("ordinary worker configuration must not break activation: %v", err)
			}
		})
	}
}

// Anything that would actually stop capture must still be detected — and then
// repaired, so the next session is healthy again without anyone intervening.
func TestActivationRepairsBrokenCaptureConfiguration(t *testing.T) {
	useTestConfigDirectory(t)
	repository := newTestRepository(t, "https://audit.example.invalid", nil)
	enableTestLocalStore(t, repository)
	repo := discoverTestRepository(t, repository)

	for _, scenario := range []struct {
		name  string
		apply func()
	}{
		{
			name:  "the Claude hook file is deleted",
			apply: func() { os.Remove(filepath.Join(repository.Root, ".claude", "settings.json")) },
		},
		{
			name: "hooks are switched off in the Claude hook file",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".claude", "settings.json"),
					`{"disableAllHooks":true,"hooks":{}}`)
			},
		},
		{
			name: "the capture hook is removed from the Codex hook file",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".codex", "hooks.json"), `{"hooks":{}}`)
			},
		},
		{
			name:  "the Copilot hook file is deleted",
			apply: func() { os.Remove(filepath.Join(repository.Root, ".github", "hooks", "prompt-audit.json")) },
		},
		{
			name: "VS Code re-enables the inherited Claude hook locations",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".vscode", "settings.json"),
					`{"chat.hookFilesLocations":{".github/hooks":false,".claude/settings.json":true},"editor.tabSize":2}`)
			},
		},
		{
			name: "an interrupted save leaves an empty settings file",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".github", "copilot", "settings.json"), "")
			},
		},
		{
			name: "the Codex project config is reformatted",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".codex", "config.toml"), "[features]\nhooks   =   true\n")
			},
		},
		{
			name: "the monitoring notice is edited",
			apply: func() {
				writeTestFile(t, filepath.Join(repository.Root, ".claude", "CLAUDE.md"), "nota personal\n")
			},
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			writeTestProviderFiles(t, repository.Root, repo.Project.EnabledTools)
			scenario.apply()
			if err := verifyProviderCaptureConfiguration(repo); err == nil {
				t.Fatal("a broken capture configuration must be detected")
			}
			repaired, err := ensureProviderCaptureConfiguration(repo)
			if err != nil {
				t.Fatalf("activation must repair the capture configuration: %v", err)
			}
			if !repaired {
				t.Fatal("activation must report that it repaired something")
			}
			if err := verifyProviderCaptureConfiguration(repo); err != nil {
				t.Fatalf("configuration must verify after repair: %v", err)
			}
		})
	}
}

// The repair merges into .vscode/settings.json instead of overwriting it: that
// file belongs to the worker and holds settings we know nothing about.
func TestVSCodeRepairPreservesWorkerSettings(t *testing.T) {
	useTestConfigDirectory(t)
	repository := newTestRepository(t, "https://audit.example.invalid", nil)
	enableTestLocalStore(t, repository)
	repo := discoverTestRepository(t, repository)

	path := filepath.Join(repository.Root, ".vscode", "settings.json")
	writeTestFile(t, path, `{"chat.hookFilesLocations":{".github/hooks":false},`+
		`"editor.rulers":[80,120],"files.exclude":{"**/.git":true}}`)

	if _, err := ensureProviderCaptureConfiguration(repo); err != nil {
		t.Fatalf("repair VS Code hook locations: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read repaired settings: %v", err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(contents, &settings); err != nil {
		t.Fatalf("repaired settings must stay valid JSON: %v", err)
	}
	var rulers []int
	if err := json.Unmarshal(settings["editor.rulers"], &rulers); err != nil {
		t.Fatalf("worker setting was not preserved: %v", err)
	}
	if len(rulers) != 2 || rulers[0] != 80 || rulers[1] != 120 {
		t.Fatalf("worker setting was not preserved: %v", rulers)
	}
	if _, ok := settings["files.exclude"]; !ok {
		t.Fatal("worker setting files.exclude was dropped")
	}
	if err := verifyVSCodeHookLocations(repository.Root, path); err != nil {
		t.Fatalf("hook locations must be correct after repair: %v", err)
	}

	// A second repair of an already-correct file must be byte-stable so it
	// never produces gratuitous working-tree churn.
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if err := repairVSCodeHookLocations(repository.Root); err != nil {
		t.Fatalf("second repair: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read settings: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("repeated repair must be byte-stable")
	}
}

// Delivery is the company's only copy. It must not be gated on the state of
// the hook files, which is exactly the coupling that used to stop publication
// after a cosmetic edit.
func TestDeliveryDoesNotDependOnProviderConfiguration(t *testing.T) {
	useTestConfigDirectory(t)
	repository := newTestRepository(t, "https://audit.example.invalid", nil)
	enableTestLocalStore(t, repository)
	repo := discoverTestRepository(t, repository)

	event := sampleEvent("hook-e-delivery", "prompt que debe entregarse")
	event.UserID = localUserID(event.UserEmail)
	event.RepositoryName = repo.Name
	event.RepositoryRemote = repositoryRemoteForEvent(repo)
	if err := writeLocalEvent(repo.Root, event); err != nil {
		t.Fatalf("store event: %v", err)
	}

	// Break the hook configuration beyond repair by making a required path a
	// directory, then confirm the already-durable prompt is still delivered.
	hookFile := filepath.Join(repository.Root, ".github", "hooks", "prompt-audit.json")
	if err := os.Remove(hookFile); err != nil {
		t.Fatalf("remove hook file: %v", err)
	}
	if err := os.MkdirAll(hookFile, 0o755); err != nil {
		t.Fatalf("replace hook file with a directory: %v", err)
	}
	if err := verifyProviderCaptureConfiguration(repo); err == nil {
		t.Fatal("the fixture must be genuinely broken for this test to mean anything")
	}

	if err := StageDirectRegistry(repository.Root); err != nil {
		t.Fatalf("commit-time delivery must not depend on hook configuration: %v", err)
	}
	staged := runGit(t, repository.Root, "diff", "--cached", "--name-only")
	if !strings.Contains(staged, ".devtools/registry/") {
		t.Fatalf("the public registry was not staged: %q", staged)
	}
}

// A prompt must never dirty the worker's tree: a permanently modified tracked
// file makes `git pull --rebase`, `git switch` and `git merge` refuse to run.
func TestCaptureLeavesTheWorkingTreeClean(t *testing.T) {
	useTestConfigDirectory(t)
	repository := newTestRepository(t, "https://audit.example.invalid", nil)
	enableTestLocalStore(t, repository)
	repo := discoverTestRepository(t, repository)

	event := sampleEvent("hook-e-clean-tree", "primer prompt")
	event.UserID = localUserID(event.UserEmail)
	event.RepositoryName = repo.Name
	event.RepositoryRemote = repositoryRemoteForEvent(repo)
	if err := writeLocalEvent(repo.Root, event); err != nil {
		t.Fatalf("store event: %v", err)
	}
	if err := StageDirectRegistry(repository.Root); err != nil {
		t.Fatalf("publish and stage: %v", err)
	}
	runGit(t, repository.Root, "commit", "-m", "deliver prompts")

	if status := runGit(t, repository.Root, "status", "--porcelain", "--untracked-files=no"); status != "" {
		t.Fatalf("tree must be clean right after delivery: %q", status)
	}

	second := sampleEvent("hook-e-clean-tree-2", "segundo prompt")
	second.UserID = event.UserID
	second.RepositoryName = repo.Name
	second.RepositoryRemote = repositoryRemoteForEvent(repo)
	second.Timestamp = event.Timestamp.Add(time.Minute)
	if err := writeLocalEvent(repo.Root, second); err != nil {
		t.Fatalf("store second event: %v", err)
	}
	if status := runGit(t, repository.Root, "status", "--porcelain", "--untracked-files=no"); status != "" {
		t.Fatalf("capturing a prompt must not modify a tracked file: %q", status)
	}
}

// An unexpected entry in the registry directory used to abort staging for
// everyone. It must be ignored instead.
func TestStagingIgnoresUnexpectedRegistryEntries(t *testing.T) {
	useTestConfigDirectory(t)
	repository := newTestRepository(t, "https://audit.example.invalid", nil)
	enableTestLocalStore(t, repository)
	repo := discoverTestRepository(t, repository)

	event := sampleEvent("hook-e-stray", "prompt con archivo intruso")
	event.UserID = localUserID(event.UserEmail)
	event.RepositoryName = repo.Name
	event.RepositoryRemote = repositoryRemoteForEvent(repo)
	if err := writeLocalEvent(repo.Root, event); err != nil {
		t.Fatalf("store event: %v", err)
	}
	if err := publishAllRegistryBackups(repo.Root); err != nil {
		t.Fatalf("publish: %v", err)
	}
	writeTestFile(t, filepath.Join(registryDir(repo.Root), ".DS_Store"), "\x00")
	writeTestFile(t, filepath.Join(registryDir(repo.Root), "notes.txt"), "hola")

	if err := StageDirectRegistry(repository.Root); err != nil {
		t.Fatalf("a stray file must not stop delivery: %v", err)
	}
	staged := runGit(t, repository.Root, "diff", "--cached", "--name-only")
	if !strings.Contains(staged, ".devtools/registry/") {
		t.Fatalf("the public registry was not staged: %q", staged)
	}
	if strings.Contains(staged, "notes.txt") || strings.Contains(staged, ".DS_Store") {
		t.Fatalf("only registry files may be staged: %q", staged)
	}
}

// The spool is the reason a busy authoritative file can no longer reject a
// worker's prompt.
func TestSpooledPromptsSurviveAndAreAbsorbed(t *testing.T) {
	useTestConfigDirectory(t)
	repository := newTestRepository(t, "https://audit.example.invalid", nil)
	enableTestLocalStore(t, repository)
	repo := discoverTestRepository(t, repository)

	event := sampleEvent("hook-e-spooled", "prompt en cola")
	event.UserID = localUserID(event.UserEmail)
	event.RepositoryName = repo.Name
	event.RepositoryRemote = repositoryRemoteForEvent(repo)
	if err := spoolLocalEvent(repo.Root, event); err != nil {
		t.Fatalf("spool event: %v", err)
	}

	absorbed, err := absorbSpooledEvents(repo.Root)
	if err != nil {
		t.Fatalf("absorb spool: %v", err)
	}
	if absorbed != 1 {
		t.Fatalf("expected one absorbed event, got %d", absorbed)
	}
	events, err := readAuthoritativeEventsForPublish(repo.Root, event.UserID)
	if err != nil {
		t.Fatalf("read authoritative backup: %v", err)
	}
	found := false
	for _, stored := range events {
		if stored.EventID == event.EventID && stored.Prompt == event.Prompt {
			found = true
		}
	}
	if !found {
		t.Fatal("the spooled prompt never reached the authoritative backup")
	}
	entries, err := os.ReadDir(spoolDir(repo.Root))
	if err != nil {
		t.Fatalf("read spool directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), registryFileExt) {
			t.Fatalf("absorbed spool file was not removed: %s", entry.Name())
		}
	}

	// Absorbing twice must be safe: a crash between append and remove leaves
	// the file behind, and the duplicate event_id has to collapse on read.
	if err := spoolLocalEvent(repo.Root, event); err != nil {
		t.Fatalf("re-spool event: %v", err)
	}
	if _, err := absorbSpooledEvents(repo.Root); err != nil {
		t.Fatalf("absorb spool again: %v", err)
	}
	events, err = readAuthoritativeEventsForPublish(repo.Root, event.UserID)
	if err != nil {
		t.Fatalf("re-read authoritative backup: %v", err)
	}
	deduped, err := dedupeAndSortChecked(events)
	if err != nil {
		t.Fatalf("dedupe: %v", err)
	}
	if len(deduped) != 1 {
		t.Fatalf("expected a single logical event after re-absorption, got %d", len(deduped))
	}
}

// Recovery correlates against direct captures whose timestamps differ, because
// the hook stamps its own clock and the transcript stamps the client's.
func TestRecoveryCorrelatesDirectCaptureAcrossClockSkew(t *testing.T) {
	transcriptTime := time.Date(2026, 7, 31, 20, 46, 34, 0, time.UTC)
	direct := model.Event{
		EventID:   "hook-e-direct",
		Timestamp: transcriptTime.Add(2200 * time.Millisecond),
		Tool:      model.ToolClaudeCode,
		SessionID: "session-a",
		Prompt:    "hola equipo",
	}
	build := func(prompt scannedPrompt) model.Event {
		return model.Event{
			EventID:   "claude-h-" + prompt.SessionID + prompt.Prompt,
			Timestamp: prompt.Timestamp,
			Tool:      model.ToolClaudeCode,
			SessionID: prompt.SessionID,
			Prompt:    prompt.Prompt,
		}
	}
	deduper := newRecoveredPromptDeduper([]model.Event{direct}, build, nil)

	sameEvent := scannedPrompt{SessionID: "session-a", Prompt: "hola equipo", Timestamp: transcriptTime}
	if !deduper.Skip(sameEvent) {
		t.Fatal("a prompt already captured directly must not be imported again")
	}
	if deduper.Skip(sameEvent) {
		t.Fatal("correlation must be one-to-one: a second transcript record has no direct capture left to claim")
	}

	// A genuinely repeated prompt far outside the window is a different event.
	deduper = newRecoveredPromptDeduper([]model.Event{direct}, build, nil)
	distant := scannedPrompt{
		SessionID: "session-a",
		Prompt:    "hola equipo",
		Timestamp: transcriptTime.Add(2 * time.Hour),
	}
	if deduper.Skip(distant) {
		t.Fatal("a prompt repeated hours later must still be recovered")
	}
}

// Viewing prompts must sweep the local transcripts first. On a fresh Codex
// clone no hook has run, so the prompt exists only in the transcript until a
// human asks to see it — and then it must appear.
func TestViewingRecoversFromLocalHistory(t *testing.T) {
	useTestConfigDirectory(t)
	repository := newTestRepository(t, "https://audit.example.invalid", nil)
	enableTestLocalStore(t, repository)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))

	codexHome := os.Getenv("CODEX_HOME")
	writeCodexRollout(t, codexHome, "unapproved-hook-session.jsonl", []map[string]any{
		meta("view-recovery", repository.Root, nil),
		userMsg("2026-07-30T12:00:00Z", "prompt que ningun hook capturo"),
	})

	// Restore the real synchronous recovery for this test; the suite disables
	// it by default so unrelated tests never scan real history.
	previous := recoverForViewingBestEffort
	recoverForViewingBestEffort = recoverForViewingBestEffortReal
	t.Cleanup(func() { recoverForViewingBestEffort = previous })

	var out bytes.Buffer
	if err := LocalLog(&out, repository.Root); err != nil {
		t.Fatalf("LocalLog: %v", err)
	}
	if !strings.Contains(out.String(), "prompt que ningun hook capturo") {
		t.Fatalf("viewing did not recover the Codex prompt from local history:\n%s", out.String())
	}
}

// The content the repair writes must be byte-identical to the committed file
// and hash to the constant the binary verifies. A drift here would make the
// agent repair a file into a state it then rejects.
func TestCanonicalRepairContentMatchesCommittedFiles(t *testing.T) {
	_, helperPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate repository root")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(helperPath), "..", "..", "..", "..", ".."))

	for _, c := range []struct {
		relative string
		content  string
		sha      string
	}{
		{".codex/AGENTS.md", canonicalCodexInstruction, canonicalCodexInstructionSHA},
		{".claude/CLAUDE.md", canonicalBootstrapInstruction, canonicalInstructionSHA},
		{".github/copilot-instructions.md", canonicalBootstrapInstruction, canonicalInstructionSHA},
		{".claude/settings.json", canonicalClaudeSettings, ""},
		{".codex/hooks.json", canonicalCodexHooks, ""},
		{".codex/config.toml", canonicalCodexConfig, ""},
		{".github/hooks/prompt-audit.json", canonicalCopilotHooks, ""},
		{".github/copilot/settings.json", canonicalCopilotSettings, ""},
	} {
		onDisk, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(c.relative)))
		if err != nil {
			t.Fatalf("read %s: %v", c.relative, err)
		}
		if string(onDisk) != c.content {
			t.Fatalf("repair content for %s differs from the committed file", c.relative)
		}
		if c.sha != "" {
			got := fmt.Sprintf("%x", sha256.Sum256([]byte(c.content)))
			if got != c.sha {
				t.Fatalf("repair content for %s hashes to %s, want %s", c.relative, got, c.sha)
			}
		}
	}
}

// A worker's Codex history can be gigabytes. Deciding from the directory entry
// that a transcript predates the clone is what keeps a fresh clone from reading
// all of it: without this, `report` on a 7 GB history took minutes.
func TestTranscriptsOlderThanTheCloneAreSkippedWithoutOpening(t *testing.T) {
	anchor := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name     string
		modified time.Time
		skip     bool
	}{
		{name: "written long before the clone", modified: anchor.Add(-24 * time.Hour), skip: true},
		{name: "written just outside the skew margin", modified: anchor.Add(-cloneAnchorClockSkew - time.Minute), skip: true},
		{name: "written inside the skew margin", modified: anchor.Add(-time.Minute), skip: false},
		{name: "written after the clone", modified: anchor.Add(time.Hour), skip: false},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "session.jsonl")
			if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, c.modified, c.modified); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := transcriptPredatesClone(info, anchor); got != c.skip {
				t.Fatalf("transcriptPredatesClone = %v, want %v", got, c.skip)
			}
		})
	}

	// A missing anchor must never let the optimisation hide a prompt.
	path := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if transcriptPredatesClone(info, time.Time{}) {
		t.Fatal("a zero anchor must never skip a transcript")
	}
	if transcriptPredatesClone(nil, anchor) {
		t.Fatal("an unavailable file info must never skip a transcript")
	}
}

func TestBackfillIntervalGovernsRespawn(t *testing.T) {
	useTestConfigDirectory(t)
	repository := newTestRepository(t, "https://audit.example.invalid", nil)
	enableTestLocalStore(t, repository)
	repo := discoverTestRepository(t, repository)

	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	if !backfillIntervalElapsed(repo.Root, now) {
		t.Fatal("a repository that never ran a backfill must be eligible")
	}
	writeBackfillState(repo.Root, now)
	if backfillIntervalElapsed(repo.Root, now.Add(time.Minute)) {
		t.Fatal("a backfill must not respawn immediately")
	}
	if !backfillIntervalElapsed(repo.Root, now.Add(backfillMinimumInterval+time.Second)) {
		t.Fatal("a backfill must become eligible again after the interval")
	}
	// A clock that jumps backwards must not suspend recovery indefinitely.
	if !backfillIntervalElapsed(repo.Root, now.Add(-time.Hour)) {
		t.Fatal("a backwards clock must not disable recovery")
	}
	if description := lastBackfillDescription(repo.Root); description == "" {
		t.Fatal("status must be able to describe the last recovery")
	}
}
