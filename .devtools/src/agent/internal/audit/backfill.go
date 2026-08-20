package audit

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Direct provider hooks are the primary capture path, but a checkout cannot
// guarantee they always run. Codex requires the worker to approve each hook
// definition before it executes, Claude and Copilot can be started with flags
// or user settings that skip project hooks, and an outdated client may not
// emit the event at all. In every one of those cases the prompt still exists
// in the provider's own local transcript.
//
// The recovery scanners already know how to import exactly the human prompts
// of this repository from those transcripts. What was missing is an automatic,
// invisible trigger: recovery used to run only when a person typed the command.
//
// scheduleBackgroundBackfill supplies that trigger. It re-executes this same
// binary as a fully detached child, so the provider hook that started it
// returns immediately and the worker never waits for a transcript scan. The
// child is rate limited and single-flighted, so frequent prompts cost nothing.

const (
	backgroundBackfillCommand  = "backfill"
	backfillStateFileName = ".backfill-state"
	backfillLockFileName  = ".backfill.lock"
	// A pass costs real work — provider transcripts can total several
	// gigabytes — so it must be rare. Nothing is lost by waiting: direct hooks
	// capture in real time, this only sweeps up what a hook could not deliver,
	// and delivery happens at commit time anyway. Half an hour keeps the cost
	// far below anything a worker could notice.
	backfillMinimumInterval   = 30 * time.Minute
	backfillStateFileMaxBytes = 128
	backfillSpawnEnv = "PROMPT_AUDIT_BACKFILL_CHILD"
	// Nobody is watching this process, so it needs its own way to stop. A
	// provider history can grow without bound, and a pass that somehow never
	// finishes would sit on an employee's machine burning CPU indefinitely.
	// The scan is resumable, so being cut off costs only the current batch.
	backfillMaximumRunDuration = 5 * time.Minute
)

// backgroundBackfillLauncher is indirected so the test suite can disable
// process spawning. A test binary is its own os.Executable(), so an unguarded
// spawn would re-enter the suite and keep temporary directories open.
var backgroundBackfillLauncher = startDetachedProcess

func backfillStatePath(repoRoot string) string {
	return filepath.Join(localStoreDir(repoRoot), backfillStateFileName)
}

func backfillLockPath(repoRoot string) string {
	return filepath.Join(localStoreDir(repoRoot), backfillLockFileName)
}

// scheduleBackgroundBackfill starts the detached recovery pass when one has not
// run recently. Every failure is silent by design: a missed backfill is retried
// on the next prompt and must never surface to the worker.
func scheduleBackgroundBackfill(repoRoot string) {
	if os.Getenv(backfillSpawnEnv) != "" {
		// Never let a backfill child schedule another backfill.
		return
	}
	if !backfillIntervalElapsed(repoRoot, time.Now().UTC()) {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		return
	}
	_ = backgroundBackfillLauncher(executable, []string{backgroundBackfillCommand}, repoRoot, []string{
		backfillSpawnEnv + "=1",
		captureRepositoryRootEnv + "=" + repoRoot,
	})
}

// RunBackgroundBackfill is the detached child entry point. It performs the same
// bounded recovery an explicit run performs, but reports nothing and returns
// success even when a scanner is partial: the caller is a background process
// whose exit status nobody observes.
func RunBackgroundBackfill(start string) {
	// Yield to the worker before touching anything. This pass is never urgent.
	enterBackgroundPriority()
	stopRunawayBackfill(backfillMaximumRunDuration)
	repo, err := DiscoverRepository(start)
	if err != nil || !repo.Project.LocalStore {
		return
	}
	// A non-blocking lock keeps concurrent sessions from scanning the same
	// transcripts at the same time. Losing the race simply means another
	// process is already doing this work.
	_ = withFileLock(backfillLockPath(repo.Root), 0, func() error {
		if !backfillIntervalElapsed(repo.Root, time.Now().UTC()) {
			return nil
		}
		// Record the attempt before the scan so a transcript that reliably
		// fails cannot make every later prompt respawn a doomed child.
		writeBackfillState(repo.Root, time.Now().UTC())
		if absorbed, err := absorbSpooledEvents(repo.Root); err != nil {
			recordLocalHealth(repo.Root, "background merge of spooled prompts was partial; it will retry later")
		} else if absorbed > 0 {
			recordLocalHealth(repo.Root, "background merge folded spooled prompts into the authoritative store")
		}
		added, scanErr := scanAndStoreAllPrompts(repo)
		if scanErr != nil {
			recordLocalHealth(repo.Root, "background prompt recovery was partial; it will retry later")
		}
		if added > 0 {
			recordLocalHealth(
				repo.Root,
				"background prompt recovery imported "+strconv.Itoa(added)+" prompts a direct hook did not deliver",
			)
		}
		// Recovered prompts land in the git-ignored authoritative backup only.
		// Publishing the tracked public copy here would dirty the worker's
		// working tree between commits, which is exactly what capture stopped
		// doing; the pre-commit hook publishes everything at commit time.
		writeBackfillState(repo.Root, time.Now().UTC())
		return nil
	})
}

// recoverForViewingBestEffort imports whatever the provider transcripts on THIS
// machine already contain, synchronously, before a human reads the registry.
//
// It exists because provider hooks are not a reliable trigger. Codex runs no
// project hook until the worker approves it with `/hooks`, so on a fresh clone
// a Codex prompt lives only in the transcript until something sweeps it up.
// When the worker (or an administrator on the same machine) runs `log` or
// `report` to see their prompts, that is exactly the moment to sweep: they are
// asking to view, and they expect what they just typed to be there.
//
// It never fails the caller. A partial scan is recorded and the view still
// renders whatever is already durable.
// recoverForViewingBestEffort is indirected so the test suite can disable the
// synchronous scan: most tests run with isolated, empty history directories,
// but the guarantee must be explicit rather than incidental.
var recoverForViewingBestEffort = recoverForViewingBestEffortReal

func recoverForViewingBestEffortReal(repo RepositoryInfo) {
	if !repo.Project.LocalStore {
		return
	}
	if _, err := absorbSpooledEvents(repo.Root); err != nil {
		recordLocalHealth(repo.Root, "spooled prompts are pending a later merge into the authoritative store")
	}
	added, scanErr := scanAndStoreAllPrompts(repo)
	if scanErr != nil {
		recordLocalHealth(repo.Root, "prompt history recovery was partial while preparing a view; it will retry later")
	}
	if added > 0 {
		recordLocalHealth(repo.Root, "prompt history recovery imported "+strconv.Itoa(added)+" prompts while preparing a view")
	}
}

// stopRunawayBackfill is the watchdog for the detached pass. It is indirected
// so the test suite, which calls RunBackgroundBackfill in-process, never arms a
// timer that would terminate the test binary.
var stopRunawayBackfill = func(budget time.Duration) {
	timer := time.AfterFunc(budget, func() { os.Exit(0) })
	// The pass is expected to finish well inside the budget; the timer only
	// exists for the case where it does not.
	_ = timer
}

func backfillIntervalElapsed(repoRoot string, now time.Time) bool {
	last, ok := readBackfillState(repoRoot)
	if !ok {
		return true
	}
	if now.Before(last) {
		// A clock moved backwards. Treat the stored stamp as stale rather than
		// suspending recovery until the clock catches up.
		return true
	}
	return now.Sub(last) >= backfillMinimumInterval
}

func readBackfillState(repoRoot string) (time.Time, bool) {
	path := backfillStatePath(repoRoot)
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return time.Time{}, false
	}
	defer file.Close()
	buffer := make([]byte, backfillStateFileMaxBytes)
	read, err := file.Read(buffer)
	if err != nil && read == 0 {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(buffer[:read])))
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func writeBackfillState(repoRoot string, at time.Time) {
	directory := localStoreDir(repoRoot)
	if err := validateDirectoryTree(repoRoot, directory); err != nil {
		return
	}
	if err := ensureDirectoryDurableUnder(repoRoot, directory, 0o700); err != nil {
		return
	}
	_ = writeFileAtomically(
		directory,
		backfillStatePath(repoRoot),
		[]byte(at.UTC().Format(time.RFC3339Nano)+"\n"),
		0o600,
	)
}

// lastBackfillDescription renders the recovery state for the status diagnostic.
func lastBackfillDescription(repoRoot string) string {
	last, ok := readBackfillState(repoRoot)
	if !ok {
		return "aún no se ha ejecutado"
	}
	return last.Format(time.RFC3339)
}
