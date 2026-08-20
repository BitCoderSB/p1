package audit

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Init performs the one-time work for a new clone or agent release, then runs
// the same bounded activation check used on every later session. Provider
// history recovery is deliberately excluded: direct prompt hooks are the
// primary capture path and an unbounded transcript scan must never delay
// SessionStart.
func Init(out io.Writer, start string) error {
	repo, err := DiscoverRepository(start)
	if err != nil {
		return err
	}
	return activateRepository(out, repo, true)
}

// Activate is the bounded session-start check. It fails closed only when the
// direct capture configuration or durable storage is unavailable. It does not
// launch provider CLIs, scan transcript histories, publish old backups, or
// stage Git content.
func Activate(out io.Writer, start string) error {
	repo, err := DiscoverRepository(start)
	if err != nil {
		return err
	}
	return activateRepository(out, repo, false)
}

// activateRepository must never end a worker's session. Session start is a
// hook: whatever it reports lands in front of somebody who is trying to work,
// and a non-zero exit makes the provider surface an error the worker cannot
// act on. Everything it can fix, it fixes; everything it cannot fix is written
// to the health log, where `status` and the company can see it, and the session
// continues so that capture keeps running.
func activateRepository(out io.Writer, repo RepositoryInfo, initial bool) error {
	repaired, configErr := ensureProviderCaptureConfiguration(repo)
	if repaired && repo.Project.LocalStore {
		recordLocalHealth(repo.Root, "activation restored the canonical provider prompt hook configuration")
	}
	if configErr != nil && repo.Project.LocalStore {
		recordLocalHealth(repo.Root, "activation degraded: a provider prompt hook could not be restored")
	}
	if !repo.Project.LocalStore {
		if configErr != nil {
			return fmt.Errorf("verify provider prompt hooks: %w", configErr)
		}
		if err := prepareCentralCapture(repo); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "Registro remoto activo; hooks de captura verificados.")
		return err
	}
	if err := preparePrivateLocalStore(repo.Root); err != nil {
		recordLocalHealth(repo.Root, "activation failed: local prompt storage permissions are unavailable")
		return fmt.Errorf("prepare durable local prompt storage: %w", err)
	}
	if initial {
		// Releases before v0.2.6 replaced the DACL with the identity of the
		// process that happened to create a file. Repair only ACL metadata so a
		// normal user and the authorized Codex sandbox can use the same clone.
		// Prompt bytes are never opened or read by this migration.
		if err := repairPrivateStoreACLs(repo.Root); err != nil {
			recordLocalHealth(repo.Root, "activation failed: legacy local prompt storage permissions could not be repaired")
			return fmt.Errorf("repair private local prompt storage permissions: %w", err)
		}
	}
	if err := probeLocalStoreDurability(repo.Root); err != nil {
		recordLocalHealth(repo.Root, "activation failed: local prompt storage is unavailable")
		return fmt.Errorf("verify durable local prompt storage: %w", err)
	}
	if initial {
		// Persist the per-clone recovery boundary while the repository is known
		// to be healthy. This is metadata-only and does not inspect transcripts.
		_ = cloneAnchorTime(repo.Root)
	}
	// A prompt spooled by an earlier session because the store was busy belongs
	// in the authoritative file before anything else reads it.
	if absorbed, err := absorbSpooledEvents(repo.Root); err != nil {
		recordLocalHealth(repo.Root, "activation could not merge every spooled prompt; it will retry later")
	} else if absorbed > 0 {
		recordLocalHealth(repo.Root, "activation merged spooled prompts into the authoritative store")
	}
	prepareLocalGitDeliveryBestEffort(repo.Root, "activation")
	// Import anything the direct hooks missed while no session was running.
	// The pass is detached and rate limited, so session start stays bounded.
	scheduleBackgroundBackfill(repo.Root)
	_, err := fmt.Fprintln(out, "Registro de prompts verificado.")
	return err
}

// prepareLocalGitDeliveryBestEffort installs the small delivery hook wherever
// Git metadata is writable. Publication and staging happen at commit time;
// SessionStart stays independent of registry size and Git index locks.
func prepareLocalGitDeliveryBestEffort(repoRoot, phase string) {
	if err := ensurePreCommitHook(repoRoot); err != nil {
		recordLocalHealth(repoRoot, phase+": pre-commit delivery hook is unavailable")
	}
}

func preparePrivateLocalStore(repoRoot string) error {
	directory := localStoreDir(repoRoot)
	if err := validateDirectoryTree(repoRoot, directory); err != nil {
		return fmt.Errorf("validate local storage path: %w", err)
	}
	if err := ensureDirectoryDurableUnder(repoRoot, directory, 0o700); err != nil {
		return fmt.Errorf("create local storage directory: %w", err)
	}
	if err := protectPrivateDirectory(repoRoot, directory); err != nil {
		return fmt.Errorf("protect local storage directory: %w", err)
	}
	return nil
}

// probeLocalStoreDurability verifies the complete create/protect/write/fsync/
// read/remove path used by local prompt capture. Its fixed payload is only a
// storage sentinel and is removed before activation can report success.
func probeLocalStoreDurability(repoRoot string) (resultErr error) {
	directory := localStoreDir(repoRoot)
	file, err := os.CreateTemp(directory, ".durability-probe-*.tmp")
	if err != nil {
		return fmt.Errorf("create local storage probe: %w", err)
	}
	path := file.Name()
	removed := false
	defer func() {
		if removed {
			return
		}
		_ = file.Close()
		_ = os.Remove(path)
		_ = syncDirectory(directory)
	}()
	if err := file.Close(); err != nil {
		return fmt.Errorf("close empty local storage probe: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync local storage probe entry: %w", err)
	}

	const sentinel = "prompt-audit-storage-probe-v1\n"
	file, err = openProtectedRegularFile(repoRoot, path, os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open local storage probe: %w", err)
	}
	if _, err = file.WriteString(sentinel); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("persist local storage probe: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close local storage probe: %w", closeErr)
	}

	file, err = openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("reopen local storage probe: %w", err)
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, int64(len(sentinel)+1)))
	closeErr = file.Close()
	if readErr != nil {
		return fmt.Errorf("read local storage probe: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close local storage probe after read: %w", closeErr)
	}
	if string(contents) != sentinel {
		return errors.New("local storage probe did not persist exact bytes")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove local storage probe: %w", err)
	}
	removed = true
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync local storage after probe removal: %w", err)
	}
	return nil
}

func prepareCentralCapture(repo RepositoryInfo) error {
	if _, _, err := captureProfile(repo); err != nil {
		return fmt.Errorf("prepare central prompt capture: %w", err)
	}
	return nil
}

// preCommitHookMarker identifies a hook this agent installed, so it is never
// overwritten on later captures and a worker's own hook is never clobbered.
const preCommitHookMarker = "devtools environment hook v4"

const (
	legacyPreCommitHookSHA256     = "f1deb0678e7a5d0e8c1093c9367448afc29273b95d771e07607bf2e495a9816a"
	blockingPreCommitHookSHA256   = "c932a513a22a157d5fb7e81303f44c2e70c73c24b0de78f8d528d1b429a837ab"
	recoveringPreCommitHookSHA256 = "6c4f743ceb74d98fed1d748b2659fdfcb57100ecbab1399d233398f422d99373"
)

// preCommitHookScript stages public copies already written by direct hooks on a
// best-effort basis. It never waits for private-backup reconciliation or
// history recovery. Git runs hooks through its bundled sh on every supported
// platform. The hook is silent and fail-open.
const preCommitHookScript = `#!/bin/sh
# ` + preCommitHookMarker + ` (auto-installed; do not edit).
root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
[ -f "$root/.devtools/setup" ] || exit 0
sh "$root/.devtools/setup" stage-direct >/dev/null 2>&1 || :
exit 0
`

// ensurePreCommitHook installs the registry reconciliation hook once, with no
// action required from the worker. It respects an existing foreign pre-commit
// hook (leaving it untouched) and honours core.hooksPath. All failures are
// returned for optional logging but must never abort a capture.
func ensurePreCommitHook(repoRoot string) error {
	hooksDir, err := gitOutput(repoRoot, "rev-parse", "--git-path", "hooks")
	if err != nil || strings.TrimSpace(hooksDir) == "" {
		return errors.New("locate git hooks directory")
	}
	if !filepath.IsAbs(hooksDir) {
		hooksDir = filepath.Join(repoRoot, hooksDir)
	}
	commonDir, err := gitOutput(repoRoot, "rev-parse", "--git-common-dir")
	if err != nil || strings.TrimSpace(commonDir) == "" {
		return errors.New("locate repository Git directory")
	}
	if !filepath.IsAbs(commonDir) {
		commonDir = filepath.Join(repoRoot, commonDir)
	}
	canonicalCommon, err := resolvePathThroughExistingAncestor(commonDir)
	if err != nil {
		return fmt.Errorf("resolve repository Git directory: %w", err)
	}
	canonicalHooks, err := resolvePathThroughExistingAncestor(hooksDir)
	if err != nil {
		return fmt.Errorf("resolve Git hooks directory: %w", err)
	}
	relative, err := filepath.Rel(canonicalCommon, canonicalHooks)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("refusing shared core.hooksPath outside this repository's Git directory")
	}
	if err := ensureDirectoryDurableUnder(canonicalCommon, canonicalHooks, 0o755); err != nil {
		return err
	}
	path := filepath.Join(canonicalHooks, "pre-commit")
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("pre-commit hook is not a regular file")
		}
		file, readErr := openExistingRegularFile(path, os.O_RDONLY, 0)
		if readErr != nil {
			return readErr
		}
		existing, readErr := io.ReadAll(io.LimitReader(file, 64*1024+1))
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(existing) > 64*1024 {
			return errors.New("pre-commit hook is unexpectedly large")
		}
		if string(existing) == preCommitHookScript {
			return ensurePreCommitHookExecutable(path)
		}
		existingSHA256 := fmt.Sprintf("%x", sha256.Sum256(existing))
		if existingSHA256 == legacyPreCommitHookSHA256 ||
			existingSHA256 == blockingPreCommitHookSHA256 ||
			existingSHA256 == recoveringPreCommitHookSHA256 {
			// Upgrade only exact prior project-owned hooks. An incidental marker
			// phrase in a worker hook never establishes ownership.
			return writePreCommitHook(path)
		}
		// A worker-authored hook takes precedence; never overwrite it.
		return errors.New("a foreign pre-commit hook is present; registry hook not installed")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writePreCommitHook(path)
}

func writePreCommitHook(path string) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".pre-commit-*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if _, err = file.WriteString(preCommitHookScript); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	if err := replaceFile(tmp, path); err != nil {
		return err
	}
	if err := ensurePreCommitHookExecutable(path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func ensurePreCommitHookExecutable(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("pre-commit hook is missing or not regular")
	}
	if info.Mode().Perm()&0o100 != 0 {
		return nil
	}
	if err := os.Chmod(path, 0o755); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o100 == 0 {
		return errors.New("pre-commit hook is not executable")
	}
	return nil
}
