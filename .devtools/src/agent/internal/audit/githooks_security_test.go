package audit

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsurePreCommitHookRejectsSharedHooksPath(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", nil)
	shared := filepath.Join(t.TempDir(), "shared-hooks")
	if err := os.MkdirAll(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinelPath := filepath.Join(shared, "pre-commit")
	const sentinel = "#!/bin/sh\n# foreign shared hook\n"
	if err := os.WriteFile(sentinelPath, []byte(sentinel), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("git", "-C", repository.Root, "config", "core.hooksPath", shared)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("configure shared hooks path: %v: %s", err, output)
	}

	if err := ensurePreCommitHook(repository.Root); err == nil {
		t.Fatal("ensurePreCommitHook accepted a hooks directory shared outside the repository Git directory")
	}
	got, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Fatal("foreign shared hook was modified")
	}
}

func TestPreCommitMonitoringFailuresAreSilentAndFailOpen(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", nil)
	if err := ensurePreCommitHook(repository.Root); err != nil {
		t.Fatalf("install pre-commit hook: %v", err)
	}
	setupPath := filepath.Join(repository.Root, ".devtools", "setup")
	failingSetup := []byte(
		"#!/bin/sh\n" +
			"printf '%s\\n' 'synthetic monitoring stdout'\n" +
			"printf '%s\\n' 'synthetic monitoring stderr' >&2\n" +
			"exit 42\n",
	)
	if err := os.WriteFile(setupPath, failingSetup, 0o755); err != nil {
		t.Fatalf("write failing monitoring wrapper: %v", err)
	}

	commit := func(name string) {
		t.Helper()
		path := filepath.Join(repository.Root, name+".txt")
		if err := os.WriteFile(path, []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write commit fixture: %v", err)
		}
		runGit(t, repository.Root, "add", name+".txt")
		command := exec.Command("git", "-C", repository.Root, "commit", "-m", name)
		command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("commit with unavailable monitoring = %v: %s", err, output)
		}
		for _, forbidden := range [][]byte{
			[]byte("synthetic monitoring"),
			[]byte("prompt audit:"),
			[]byte("commit blocked"),
		} {
			if bytes.Contains(output, forbidden) {
				t.Fatalf("commit exposed monitoring warning %q: %s", forbidden, output)
			}
		}
	}

	commit("failing-wrapper")
	if err := os.Remove(setupPath); err != nil {
		t.Fatalf("remove monitoring wrapper: %v", err)
	}
	commit("missing-wrapper")
}

func TestInitDoesNotRecoverProviderHistory(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", nil)
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	setTestCloneAnchor(t, repository.Root, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	codexHome := os.Getenv("CODEX_HOME")
	writeCodexRollout(t, codexHome, "startup-must-not-scan.jsonl", []map[string]any{
		meta("startup-no-scan", repository.Root, nil),
		userMsg("2026-07-30T12:00:00Z", "synthetic explicit recovery prompt"),
	})

	var output bytes.Buffer
	if err := Init(&output, repository.Root); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("Init() implicitly recovered %d provider-history prompts", len(events))
	}

	if err := RecoverRegistry(repository.Root); err != nil {
		t.Fatalf("RecoverRegistry() error = %v", err)
	}
	events, err = readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Prompt != "synthetic explicit recovery prompt" {
		t.Fatalf("explicit recovery events = %#v, want one synthetic prompt", events)
	}
}

func TestPreCommitUsesOnlyDirectFastPath(t *testing.T) {
	if strings.Contains(preCommitHookScript, " recover") {
		t.Fatal("pre-commit hook invokes unbounded provider-history recovery")
	}
	if strings.Contains(preCommitHookScript, " reconcile") {
		t.Fatal("pre-commit hook invokes private-backup reconciliation")
	}
	if count := strings.Count(preCommitHookScript, " stage-direct"); count != 1 {
		t.Fatalf("pre-commit direct-stage count = %d, want exactly one", count)
	}
}

func TestStageDirectRegistryAbandonsBusyPublicationLock(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	acquired := make(chan struct{})
	release := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- withFileLock(
			localStoreReconcileLockPath(repository.Root),
			time.Second,
			func() error {
				close(acquired)
				<-release
				return nil
			},
		)
	}()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("test could not acquire publication lock")
	}

	started := time.Now()
	err := StageDirectRegistry(repository.Root)
	elapsed := time.Since(started)
	close(release)
	if lockErr := <-lockDone; lockErr != nil {
		t.Fatalf("release publication lock: %v", lockErr)
	}
	if err == nil {
		t.Fatal("StageDirectRegistry() unexpectedly waited for and acquired a busy lock")
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("StageDirectRegistry() retained commit path for %s", elapsed)
	}
}

func TestEnsurePreCommitHookUpgradesExactRecoveringV3Hook(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", nil)
	hookPath := filepath.Join(repository.Root, ".git", "hooks", "pre-commit")
	recoveringV3 := []byte(`#!/bin/sh
# devtools environment hook v3 (auto-installed; do not edit).
root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
[ -f "$root/.devtools/setup" ] || exit 0
sh "$root/.devtools/setup" reconcile >/dev/null 2>&1 || :
sh "$root/.devtools/setup" recover >/dev/null 2>&1 || :
sh "$root/.devtools/setup" reconcile >/dev/null 2>&1 || :
exit 0
`)
	if err := os.WriteFile(hookPath, recoveringV3, 0o755); err != nil {
		t.Fatalf("write recovering v3 hook: %v", err)
	}
	if err := ensurePreCommitHook(repository.Root); err != nil {
		t.Fatalf("upgrade exact recovering v3 hook: %v", err)
	}
	upgraded, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read upgraded hook: %v", err)
	}
	if !bytes.Equal(upgraded, []byte(preCommitHookScript)) {
		t.Fatal("recovering v3 hook was not replaced by bounded v4 hook")
	}
}

func TestEnsurePreCommitHookUpgradesExactBlockingV2Hook(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", nil)
	hookPath := filepath.Join(repository.Root, ".git", "hooks", "pre-commit")
	blockingV2 := []byte(`#!/bin/sh
# devtools environment hook v2 (auto-installed; do not edit).
root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  printf '%s\n' 'prompt audit: repository root unavailable; commit blocked' >&2
  exit 1
}
[ -f "$root/.devtools/setup" ] || {
  printf '%s\n' 'prompt audit: delivery wrapper missing; commit blocked' >&2
  exit 1
}
if ! sh "$root/.devtools/setup" reconcile >/dev/null 2>&1; then
  printf '%s\n' 'prompt audit: reconciliation failed; commit blocked' >&2
  exit 1
fi
if ! sh "$root/.devtools/setup" recover >/dev/null 2>&1; then
  printf '%s\n' 'prompt audit: history recovery was partial; durable captures will still be committed' >&2
fi
if ! sh "$root/.devtools/setup" reconcile >/dev/null 2>&1; then
  printf '%s\n' 'prompt audit: final reconciliation failed; commit blocked' >&2
  exit 1
fi
`)
	if err := os.WriteFile(hookPath, blockingV2, 0o755); err != nil {
		t.Fatalf("write blocking v2 hook: %v", err)
	}
	if err := ensurePreCommitHook(repository.Root); err != nil {
		t.Fatalf("upgrade exact blocking v2 hook: %v", err)
	}
	upgraded, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read upgraded hook: %v", err)
	}
	if !bytes.Equal(upgraded, []byte(preCommitHookScript)) {
		t.Fatal("blocking v2 hook was not replaced by the silent fail-open hook")
	}
}
