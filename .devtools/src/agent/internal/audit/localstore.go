package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/acme/prompt-audit-template/internal/model"
)

// Committed-registry demo mode. When project.json sets "local_store": true, the
// agent maintains two per-user representations of captured prompts:
//
//   - An authoritative backup under .devtools/local-store/<user>.jsonl that
//     is git-ignored, so no Git operation (checkout, reset, rebase) can revert
//     or lose it. This is the source of truth on each machine.
//   - A committed registry under .devtools/registry/<user>.jsonl that is
//     rebuilt as the union of (existing registry, authoritative backup). It is
//     what travels in commits so the company can review it after a pull.
//
// Per-user files plus a merge=union attribute reduce cross-worker conflicts.
// Direct hooks fsync the private backup first and then publish a working-tree
// registry copy without touching .git. Session bootstrap and pre-commit
// reconciliation additionally stage that copy wherever Git metadata is
// writable.
const (
	localStoreDirName       = "local-store"
	registryDirName         = "registry"
	registryFileExt         = ".jsonl"
	repositoryIdentityFile  = ".repository-identity-v1"
	localStoreLockTimeout   = 8 * time.Second
	localCaptureLockTimeout = 20 * time.Second
	// Publication is secondary to the already-durable private append and runs
	// inside a 30-second provider hook. Never spend the general reconciliation
	// timeout merely waiting to append its public working-tree copy.
	directRegistryLockTimeout = 500 * time.Millisecond
	// The pre-commit hook rebuilds and stages the public copy under the same
	// short budget: a commit must never feel blocked. If another process holds
	// the lock, this commit delivers what was already published and the next
	// one catches up.
	commitPublishLockTimeout = directRegistryLockTimeout
	maxRegistryStageFile      = 128 * 1024 * 1024
	maxRegistryStageTotal     = 512 * 1024 * 1024
)

func localStoreDir(repoRoot string) string {
	return filepath.Join(repoRoot, ".devtools", localStoreDirName)
}

func registryDir(repoRoot string) string {
	return filepath.Join(repoRoot, ".devtools", registryDirName)
}

func authoritativePath(repoRoot, userID string) string {
	return filepath.Join(localStoreDir(repoRoot), userID+registryFileExt)
}

func registryPath(repoRoot, userID string) string {
	return filepath.Join(registryDir(repoRoot), userID+registryFileExt)
}

func localStoreReconcileLockPath(repoRoot string) string {
	return filepath.Join(localStoreDir(repoRoot), ".reconcile.lock")
}

func localStoreDeliveryBarrierLockPath(repoRoot string) string {
	return filepath.Join(localStoreDir(repoRoot), ".delivery-barrier.lock")
}

func localStoreCaptureLockPath(repoRoot, userID string) string {
	sum := sha256.Sum256([]byte(userID))
	return filepath.Join(localStoreDir(repoRoot), ".capture-"+hex.EncodeToString(sum[:8])+".lock")
}

// localUserID derives a stable, filesystem-safe identifier from the worker email
// so per-user files never collide and the viewer can group by user.
func localUserID(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return "local-" + hex.EncodeToString(sum[:8])
}

// writeLocalEvent appends and syncs the event to the authoritative backup.
// Delivery work must never hold this write behind its repository-wide barrier:
// the per-user capture lock is sufficient to serialize append/tail repair with
// authoritative snapshots. A reconciliation that already took its snapshot may
// deliver this event on the next pass, but the prompt is durable immediately.
func writeLocalEvent(repoRoot string, event model.Event) error {
	if err := validateStoredEvent(event); err != nil {
		return fmt.Errorf("refuse invalid local event before durable append: %w", err)
	}
	if err := validateDirectoryTree(repoRoot, localStoreDir(repoRoot)); err != nil {
		return fmt.Errorf("validate local backup path: %w", err)
	}
	if err := ensureDirectoryDurableUnder(repoRoot, localStoreDir(repoRoot), 0o700); err != nil {
		return fmt.Errorf("create local backup directory: %w", err)
	}
	if err := protectPrivateDirectory(repoRoot, localStoreDir(repoRoot)); err != nil {
		return fmt.Errorf("protect local backup directory: %w", err)
	}
	return withFileLock(
		localStoreCaptureLockPath(repoRoot, event.UserID),
		localCaptureLockTimeout,
		func() error {
			recovered, err := appendEvent(repoRoot, authoritativePath(repoRoot, event.UserID), event)
			if err != nil {
				return err
			}
			if recovered {
				recordLocalHealth(repoRoot, "repaired an incomplete trailing JSONL record before capture")
			}
			return nil
		},
	)
}

// ReconcileRegistry explicitly rebuilds every user's committed registry file
// from its authoritative backup. Recovery scanners remain independent, and
// publication, validation and staging errors are returned to the caller. The
// pre-commit hook uses StageDirectRegistry instead so it never waits for this
// full private-backup operation.
// Delivery never depends on the state of the provider hook files. Prompts that
// are already durable belong to the company, so a drifted or repaired hook
// configuration must not be able to hold them back: publication is the one
// operation that must keep working while everything else is being fixed.
func ReconcileRegistry(start string) error {
	repo, err := DiscoverRepository(start)
	if err != nil {
		return err
	}
	if !repo.Project.LocalStore {
		return nil
	}
	return reconcileLocalRegistry(repo.Root)
}

// reconcileLocalRegistry is the fast, fail-closed delivery operation used by
// the silent fail-open pre-commit hook and after an explicit recovery. The
// barrier serializes legacy capture processes and complete publication/staging
// passes. Current direct capture uses only the per-user capture lock: an event
// that arrives after a publication snapshot remains durable and is delivered
// on the next pass.
func reconcileLocalRegistry(repoRoot string) error {
	// Fold any spooled prompt back into the authoritative file first, so this
	// pass publishes a complete history. Absorption takes the per-user capture
	// lock itself and must therefore run outside the delivery barrier.
	if _, err := absorbSpooledEvents(repoRoot); err != nil {
		recordLocalHealth(repoRoot, "spooled prompts are pending a later merge into the authoritative store")
	}
	return withFileLock(localStoreDeliveryBarrierLockPath(repoRoot), localCaptureLockTimeout, func() error {
		return withFileLock(localStoreReconcileLockPath(repoRoot), localStoreLockTimeout, func() error {
			if err := publishAllRegistryBackupsUnlocked(repoRoot); err != nil {
				return err
			}
			return stagePromptRegistryUnlocked(repoRoot)
		})
	})
}

// RecoverRegistry explicitly scans provider histories as a batch-bounded,
// secondary contingency path. It is never invoked by SessionStart,
// status/report/log, or pre-commit because total external transcript size is
// outside this project's latency control.
func RecoverRegistry(start string) error {
	repo, err := DiscoverRepository(start)
	if err != nil {
		return err
	}
	if !repo.Project.LocalStore {
		return nil
	}
	_, scanErr := scanAndStoreAllPrompts(repo)
	if scanErr != nil {
		recordLocalHealth(repo.Root, "prompt history recovery was partial during reconciliation")
	}
	return errors.Join(scanErr, reconcileLocalRegistry(repo.Root))
}

type registryStageSnapshot struct {
	relative string
	data     []byte
	events   []model.Event
	oid      string
}

type registryIndexEntry struct {
	mode  string
	oid   string
	stage string
}

func stagePromptRegistry(repoRoot string) error {
	return withFileLock(localStoreReconcileLockPath(repoRoot), localStoreLockTimeout, func() error {
		return stagePromptRegistryUnlocked(repoRoot)
	})
}

// StageDirectRegistry is the commit-time delivery path, and the only routine
// operation that writes the public registry. Rebuilding it here — rather than
// on every prompt — is what keeps the worker's working tree clean between
// commits: the file is written and staged inside the same commit, so the tree
// matches HEAD again as soon as the commit completes.
//
// It stays bounded and fail-open. A busy publication lock is abandoned quickly;
// the pre-commit hook never waits for the 20 s delivery barrier or the 8 s
// explicit reconciliation lock, and prompts it could not publish stay in the
// authoritative backup for the next commit.
func StageDirectRegistry(start string) error {
	repo, err := DiscoverRepository(start)
	if err != nil {
		return err
	}
	if !repo.Project.LocalStore {
		return nil
	}
	// Prompts spooled while the authoritative file was busy belong in this
	// commit too, but absorbing them must never delay it.
	if _, absorbErr := absorbSpooledEvents(repo.Root); absorbErr != nil {
		recordLocalHealth(repo.Root, "spooled prompts are pending a later merge into the authoritative store")
	}
	// A commit is the worker's own action and does not depend on any provider
	// hook, so it is the most reliable place to sweep up Codex prompts that a
	// never-approved hook could not capture. It runs detached so the commit is
	// never slowed; those prompts land in the next commit.
	scheduleBackgroundBackfill(repo.Root)
	return withFileLock(
		localStoreReconcileLockPath(repo.Root),
		commitPublishLockTimeout,
		func() error {
			if err := publishAllRegistryBackupsUnlocked(repo.Root); err != nil {
				// Stage whatever is already published rather than delivering
				// nothing at all.
				recordLocalHealth(repo.Root, "commit-time registry publication was incomplete; it will retry on the next commit")
			}
			return stagePromptRegistryUnlocked(repo.Root)
		},
	)
}

func stagePromptRegistryUnlocked(repoRoot string) error {
	snapshots, err := snapshotPromptRegistry(repoRoot)
	if err != nil {
		return fmt.Errorf("validate prompt registry before staging: %w", err)
	}
	expected := make(map[string]*registryStageSnapshot, len(snapshots))
	for index := range snapshots {
		expected[snapshots[index].relative] = &snapshots[index]
	}

	before, err := readRegistryIndex(repoRoot)
	if err != nil {
		return fmt.Errorf("inspect prompt registry index: %w", err)
	}
	// A registry path that is tracked but no longer in the working tree is left
	// exactly as the index already has it: this pass never stages a deletion,
	// and one absent file must not stop every other worker's prompts from being
	// delivered. Its content is still recoverable from the private backup.
	untouched := make(map[string]struct{})
	for path, entries := range before {
		if _, ok := expected[path]; !ok {
			untouched[path] = struct{}{}
		}
		for _, entry := range entries {
			if entry.stage != "0" {
				return errors.New("unmerged prompt registry entry refused")
			}
		}
	}

	for index := range snapshots {
		snapshot := &snapshots[index]
		if _, tracked := before[snapshot.relative]; tracked {
			if err := clearRegistryIndexFlags(repoRoot, snapshot.relative); err != nil {
				return err
			}
		}
		oidBytes, err := runGitBytes(
			repoRoot,
			snapshot.data,
			"hash-object", "-w", "--no-filters", "--stdin",
		)
		if err != nil {
			return errors.New("write exact prompt registry blob")
		}
		snapshot.oid = strings.TrimSpace(string(oidBytes))
		if !validGitObjectID(snapshot.oid) {
			return errors.New("Git returned an invalid prompt registry object id")
		}
		if _, err := runGitBytes(
			repoRoot,
			nil,
			"update-index", "--add", "--cacheinfo", "100644", snapshot.oid, snapshot.relative,
		); err != nil {
			return errors.New("stage exact prompt registry blob")
		}
		if err := clearRegistryIndexFlags(repoRoot, snapshot.relative); err != nil {
			return err
		}
	}

	deleted, err := gitOutput(
		repoRoot,
		"diff", "--cached", "--name-only", "--diff-filter=D", "--", ".devtools/registry",
	)
	if err != nil {
		return errors.New("verify prompt registry deletions")
	}
	if strings.TrimSpace(deleted) != "" {
		return errors.New("staged prompt registry deletion refused")
	}

	after, err := readRegistryIndex(repoRoot)
	if err != nil {
		return fmt.Errorf("verify prompt registry index: %w", err)
	}
	if len(after) != len(expected)+len(untouched) {
		return errors.New("staged prompt registry set does not match the validated snapshot")
	}
	for path, snapshot := range expected {
		entries := after[path]
		if len(entries) != 1 || entries[0].stage != "0" ||
			entries[0].mode != "100644" || entries[0].oid != snapshot.oid {
			return errors.New("staged prompt registry metadata does not match the validated snapshot")
		}
		blob, err := runGitBytes(repoRoot, nil, "cat-file", "blob", snapshot.oid)
		if err != nil || !bytes.Equal(blob, snapshot.data) {
			return errors.New("staged prompt registry bytes do not match the validated snapshot")
		}
		if err := verifyRegistryIndexFlags(repoRoot, path); err != nil {
			return err
		}
	}

	rechecked, err := snapshotPromptRegistry(repoRoot)
	if err != nil || !sameRegistrySnapshots(snapshots, rechecked) {
		return errors.New("prompt registry changed while it was being staged")
	}
	return nil
}

func snapshotPromptRegistry(repoRoot string) ([]registryStageSnapshot, error) {
	directory := registryDir(repoRoot)
	if err := validateDirectoryTree(repoRoot, directory); err != nil {
		return nil, fmt.Errorf("validate prompt registry path: %w", err)
	}
	directoryInfo, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect prompt registry directory: %w", err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return nil, errors.New("prompt registry directory is not a regular directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, errors.New("read prompt registry directory")
	}
	snapshots := make([]registryStageSnapshot, 0, len(entries))
	var all []model.Event
	var totalBytes int64
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, registryFileExt) {
			// A .DS_Store, a merge .orig, an editor swap file or a directory
			// someone dropped in here is not ours to interpret — but it is also
			// no reason to stop delivering prompts. Ignore it and stage the
			// registry files that are actually present.
			continue
		}
		path := filepath.Join(directory, name)
		file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
		if err != nil {
			return nil, errors.New("open regular prompt registry snapshot")
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil ||
			openedInfo.Size() < 0 ||
			openedInfo.Size() > maxRegistryStageFile ||
			totalBytes > maxRegistryStageTotal-openedInfo.Size() {
			_ = file.Close()
			return nil, errors.New("prompt registry snapshot exceeds the bounded staging size")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxRegistryStageFile+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil ||
			int64(len(data)) != openedInfo.Size() ||
			len(data) > maxRegistryStageFile {
			return nil, errors.New("read stable prompt registry snapshot")
		}
		totalBytes += int64(len(data))
		events, err := decodeStoredEventsBytes(name, data)
		if err != nil {
			return nil, err
		}
		userID := strings.TrimSuffix(name, registryFileExt)
		if err := validateStoredEventsForContext(repoRoot, userID, events); err != nil {
			return nil, fmt.Errorf("prompt registry contains an out-of-scope event: %w", err)
		}
		snapshots = append(snapshots, registryStageSnapshot{
			relative: filepath.ToSlash(filepath.Join(".devtools", "registry", name)),
			data:     data,
			events:   events,
		})
		all = append(all, events...)
	}
	if _, err := dedupeAndSortChecked(all); err != nil {
		return nil, err
	}
	sort.Slice(snapshots, func(left, right int) bool {
		return snapshots[left].relative < snapshots[right].relative
	})
	return snapshots, nil
}

func decodeStoredEventsBytes(name string, data []byte) ([]model.Event, error) {
	var events []model.Event
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if len(scanner.Bytes()) == 0 {
			continue
		}
		event, err := decodeStoredEventLine(scanner.Bytes())
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid JSON on line %d", name, lineNumber)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("scan prompt registry snapshot")
	}
	return events, nil
}

func readRegistryIndex(repoRoot string) (map[string][]registryIndexEntry, error) {
	output, err := runGitBytes(
		repoRoot,
		nil,
		"ls-files", "--stage", "-z", "--", ".devtools/registry",
	)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]registryIndexEntry)
	for _, record := range bytes.Split(output, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, pathBytes, found := bytes.Cut(record, []byte{'\t'})
		fields := strings.Fields(string(header))
		if !found || len(fields) != 3 {
			return nil, errors.New("invalid prompt registry index record")
		}
		path := filepath.ToSlash(string(pathBytes))
		result[path] = append(result[path], registryIndexEntry{
			mode: fields[0], oid: fields[1], stage: fields[2],
		})
	}
	return result, nil
}

func clearRegistryIndexFlags(repoRoot, path string) error {
	if _, err := runGitBytes(
		repoRoot,
		nil,
		"update-index", "--no-assume-unchanged", "--no-skip-worktree", "--", path,
	); err != nil {
		return errors.New("clear prompt registry index flags")
	}
	return nil
}

func verifyRegistryIndexFlags(repoRoot, path string) error {
	verbose, err := runGitBytes(repoRoot, nil, "ls-files", "-v", "-z", "--", path)
	if err != nil || len(verbose) < 2 || verbose[1] != ' ' ||
		(verbose[0] >= 'a' && verbose[0] <= 'z') || verbose[0] == 'S' {
		return errors.New("prompt registry index flags are unsafe")
	}
	tagged, err := runGitBytes(repoRoot, nil, "ls-files", "-t", "-z", "--", path)
	if err != nil || len(tagged) < 2 || tagged[1] != ' ' || tagged[0] == 'S' {
		return errors.New("prompt registry skip-worktree flag remains set")
	}
	return nil
}

func runGitBytes(repoRoot string, input []byte, args ...string) ([]byte, error) {
	fullArgs := append([]string{"-C", repoRoot}, args...)
	command := exec.Command("git", fullArgs...)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	hideChildConsole(command)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	return command.Output()
}

func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func sameRegistrySnapshots(left, right []registryStageSnapshot) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].relative != right[index].relative ||
			!bytes.Equal(left[index].data, right[index].data) {
			return false
		}
	}
	return true
}

func publishAllRegistryBackups(repoRoot string) error {
	return withFileLock(localStoreReconcileLockPath(repoRoot), localStoreLockTimeout, func() error {
		return publishAllRegistryBackupsUnlocked(repoRoot)
	})
}

func publishAllRegistryBackupsUnlocked(repoRoot string) error {
	if err := validateDirectoryTree(repoRoot, localStoreDir(repoRoot)); err != nil {
		return fmt.Errorf("validate local backup path: %w", err)
	}
	directoryInfo, err := os.Lstat(localStoreDir(repoRoot))
	localStoreExists := err == nil
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect local backups: %w", err)
		}
	} else if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return errors.New("local backup path is not a regular directory")
	}
	userIDs := make(map[string]struct{})
	if localStoreExists {
		entries, err := os.ReadDir(localStoreDir(repoRoot))
		if err != nil {
			return fmt.Errorf("read local backups: %w", err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !entry.IsDir() && strings.HasSuffix(name, registryFileExt) {
				userIDs[strings.TrimSuffix(name, registryFileExt)] = struct{}{}
			}
		}
	}
	if err := validateDirectoryTree(repoRoot, registryDir(repoRoot)); err != nil {
		return err
	}
	registryEntries, registryErr := os.ReadDir(registryDir(repoRoot))
	if registryErr != nil && !errors.Is(registryErr, os.ErrNotExist) {
		return fmt.Errorf("read prompt registry: %w", registryErr)
	}
	for _, entry := range registryEntries {
		name := entry.Name()
		if !entry.IsDir() && strings.HasSuffix(name, registryFileExt) {
			userIDs[strings.TrimSuffix(name, registryFileExt)] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(userIDs))
	for userID := range userIDs {
		ordered = append(ordered, userID)
	}
	sort.Strings(ordered)
	var problems []error
	for _, userID := range ordered {
		if err := publishRegistryUnlocked(repoRoot, userID); err != nil {
			problems = append(problems, err)
		}
	}
	if err := errors.Join(problems...); err != nil {
		return err
	}
	return markRepositoryIdentityMigrationComplete(repoRoot)
}

// publishRegistryUnlocked writes registry/<user>.jsonl as the deduplicated,
// chronologically sorted union of the existing registry file and the
// authoritative backup. It never removes an event already present in either.
func publishRegistryUnlocked(repoRoot, userID string) error {
	if err := validateDirectoryTree(repoRoot, localStoreDir(repoRoot)); err != nil {
		return fmt.Errorf("validate local backup path: %w", err)
	}
	if err := validateDirectoryTree(repoRoot, registryDir(repoRoot)); err != nil {
		return fmt.Errorf("validate prompt registry path: %w", err)
	}
	backup, err := readAuthoritativeEventsForPublish(repoRoot, userID)
	if err != nil {
		return err
	}
	backup, err = dedupeAndSortChecked(backup)
	if err != nil {
		return fmt.Errorf("authoritative backup conflict: %w", err)
	}
	path := registryPath(repoRoot, userID)
	registryInfo, statErr := os.Lstat(path)
	registryExisted := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect registry before publication: %w", statErr)
	}
	if registryExisted &&
		(registryInfo.Mode()&os.ModeSymlink != 0 || !registryInfo.Mode().IsRegular()) {
		return errors.New("existing prompt registry is not a regular file")
	}
	rebuildRequired := false
	existing, readErr := readEventsFile(path)
	if readErr == nil {
		var migrated bool
		existing, migrated, readErr = normalizeStoredEventsForContext(repoRoot, userID, existing)
		rebuildRequired = migrated
	}
	if readErr != nil {
		digest, snapshotErr := sha256File(path)
		if snapshotErr != nil {
			return errors.Join(readErr, fmt.Errorf("digest invalid registry for quarantine: %w", snapshotErr))
		}
		digestRecord := []byte(fmt.Sprintf("source=%s\nsha256=%s\n",
			filepath.Base(path), digest))
		// Unknown fields may themselves contain an assistant response. Preserve
		// only a digest as tamper evidence; never copy the invalid payload.
		if snapshotErr := quarantineRegistryBytes(repoRoot, filepath.Base(path)+".digest", digestRecord); snapshotErr != nil {
			return errors.Join(readErr, snapshotErr)
		}
		salvaged, salvageErr := readValidEventsFile(path)
		if salvageErr != nil {
			return errors.Join(readErr, salvageErr)
		}
		var contextInvalid bool
		salvaged, contextInvalid, salvageErr = filterStoredEventsForContext(repoRoot, userID, salvaged)
		if salvageErr != nil {
			return errors.Join(readErr, salvageErr)
		}
		rebuildRequired = rebuildRequired || contextInvalid
		recordLocalHealth(repoRoot, "invalid registry quarantined; authoritative backup used for rebuild")
		existing = salvaged
		rebuildRequired = true
	}

	seen := make(map[string]model.Event, len(backup)+len(existing))
	for _, event := range backup {
		seen[event.EventID] = event
	}
	accepted := make([]model.Event, 0, len(existing))
	conflicts := make([]model.Event, 0)
	for _, event := range existing {
		if previous, duplicate := seen[event.EventID]; duplicate {
			if !sameLogicalStoredEvent(previous, event) {
				conflicts = append(conflicts, event)
				rebuildRequired = true
			}
			continue
		}
		seen[event.EventID] = event
		accepted = append(accepted, event)
	}
	if len(conflicts) > 0 {
		payload, encodeErr := encodeEventsJSONL(conflicts)
		if encodeErr != nil {
			return encodeErr
		}
		if err := quarantineRegistryBytes(repoRoot, filepath.Base(path)+".conflicts", payload); err != nil {
			return err
		}
		recordLocalHealth(repoRoot, "conflicting registry rows quarantined; authoritative rows retained")
	}
	// The private backup is authoritative; nonconflicting remote rows remain so
	// Git union transport does not erase prompts captured on another machine.
	merged, err := dedupeAndSortChecked(append(backup, accepted...))
	if err != nil {
		return err
	}
	if len(merged) == 0 && !registryExisted && !rebuildRequired {
		return nil
	}
	if registryExisted && !rebuildRequired && storedEventsEqual(existing, merged) {
		return nil
	}
	if err := ensureDirectoryDurableUnder(repoRoot, registryDir(repoRoot), 0o755); err != nil {
		return fmt.Errorf("create registry directory: %w", err)
	}
	return writeEventsFileAtomic(path, merged)
}

func storedEventsEqual(left, right []model.Event) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !sameLogicalStoredEvent(left[index], right[index]) {
			return false
		}
	}
	return true
}

func markRepositoryIdentityMigrationComplete(repoRoot string) error {
	directory := localStoreDir(repoRoot)
	if err := ensureDirectoryDurableUnder(repoRoot, directory, 0o700); err != nil {
		return err
	}
	path := filepath.Join(directory, repositoryIdentityFile)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("repository identity marker is not a regular file")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(directory, ".repository-identity-*.tmp")
	if err != nil {
		return fmt.Errorf("create repository identity marker: %w", err)
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if _, err = file.WriteString("v1\n"); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("persist repository identity marker: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close repository identity marker: %w", closeErr)
	}
	if err := protectFile(repoRoot, tmp); err != nil {
		return err
	}
	if err := replaceFile(tmp, path); err != nil {
		return fmt.Errorf("replace repository identity marker: %w", err)
	}
	return syncDirectory(directory)
}

func readAuthoritativeEventsForPublish(repoRoot, userID string) ([]model.Event, error) {
	events, _, err := readAuthoritativeEventsSnapshot(repoRoot, userID)
	return events, err
}

// readAuthoritativeEventsSnapshot returns a strict, capture-lock-protected
// snapshot and its exact append boundary. Publication and history recovery must
// never accept an unlocked "valid prefix": a concurrent append can be fully
// valid while still landing just after the reader observed EOF.
func readAuthoritativeEventsSnapshot(repoRoot, userID string) ([]model.Event, int64, error) {
	path := authoritativePath(repoRoot, userID)
	var snapshot []model.Event
	var boundary int64
	err := withFileLock(localStoreCaptureLockPath(repoRoot, userID), localCaptureLockTimeout, func() error {
		var err error
		snapshot, boundary, _, _, err = readAuthoritativeEventsSnapshotUnlocked(
			repoRoot,
			userID,
			path,
		)
		return err
	})
	return snapshot, boundary, err
}

func readAuthoritativeEventsSnapshotUnlocked(
	repoRoot,
	userID,
	path string,
) ([]model.Event, int64, authoritativeFingerprint, bool, error) {
	current, lockedReadErr := readEventsFile(path)
	migrated := false
	if lockedReadErr == nil {
		current, migrated, lockedReadErr = normalizeStoredEventsForContext(repoRoot, userID, current)
	}
	if lockedReadErr == nil {
		if migrated {
			if err := writePrivateEventsFileAtomic(repoRoot, path, current); err != nil {
				return nil, 0, authoritativeFingerprint{}, false,
					fmt.Errorf("migrate stable repository identity: %w", err)
			}
			recordLocalHealth(repoRoot, "legacy repository identity migrated without removing prompt events")
		}
	} else {
		digest, snapshotErr := sha256File(path)
		if snapshotErr != nil {
			return nil, 0, authoritativeFingerprint{}, false, errors.Join(
				lockedReadErr,
				fmt.Errorf("digest invalid authoritative backup: %w", snapshotErr),
			)
		}
		digestRecord := []byte(fmt.Sprintf("source=%s\nsha256=%s\n",
			filepath.Base(path), digest))
		// A malformed row may contain fields outside the prompt-only contract.
		// Preserve tamper evidence without copying its payload.
		if err := quarantineRegistryBytes(
			repoRoot,
			filepath.Base(path)+".authoritative.digest",
			digestRecord,
		); err != nil {
			return nil, 0, authoritativeFingerprint{}, false, errors.Join(lockedReadErr, err)
		}
		salvaged, salvageErr := readValidEventsFile(path)
		if salvageErr != nil {
			return nil, 0, authoritativeFingerprint{}, false, errors.Join(lockedReadErr, salvageErr)
		}
		salvaged, _, salvageErr = filterStoredEventsForContext(repoRoot, userID, salvaged)
		if salvageErr != nil {
			return nil, 0, authoritativeFingerprint{}, false, errors.Join(lockedReadErr, salvageErr)
		}
		if err := writePrivateEventsFileAtomic(repoRoot, path, salvaged); err != nil {
			return nil, 0, authoritativeFingerprint{}, false, errors.Join(lockedReadErr, err)
		}
		recordLocalHealth(repoRoot, "invalid authoritative backup quarantined and rebuilt from strict prompt rows")
	}

	snapshot, fingerprint, present, err := readStableAuthoritativeEventsFile(
		repoRoot,
		userID,
		path,
	)
	if err != nil {
		return nil, 0, authoritativeFingerprint{}, false, err
	}
	if !present {
		return nil, 0, authoritativeFingerprint{}, false, nil
	}
	return snapshot, fingerprint.Size, fingerprint, true, nil
}

// readStableAuthoritativeEventsFile parses and hashes one fixed-size view from
// the same verified handle. It then proves that the handle and pathname still
// identify that unchanged file, so recovery never pairs events from one
// generation with a fingerprint from another.
func readStableAuthoritativeEventsFile(
	repoRoot,
	userID,
	path string,
) ([]model.Event, authoritativeFingerprint, bool, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, authoritativeFingerprint{}, false, nil
	}
	if err != nil {
		return nil, authoritativeFingerprint{}, false,
			fmt.Errorf("open authoritative snapshot: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, authoritativeFingerprint{}, false,
			fmt.Errorf("stat authoritative snapshot: %w", err)
	}
	tracker := newFileContentTracker()
	reader := io.TeeReader(io.NewSectionReader(file, 0, opened.Size()), tracker)
	events := make([]model.Event, 0)
	readErr := forEachBoundedJSONLLine(reader, 8*1024*1024, func(line []byte, oversized bool) error {
		if oversized {
			return errors.New("authoritative snapshot contains an oversized event")
		}
		event, decodeErr := decodeStoredEventLine(line)
		if decodeErr != nil {
			return errors.New("authoritative snapshot contains an invalid event")
		}
		events = append(events, event)
		return nil
	})
	identity, identityErr := tracker.identity(opened.Size(), opened.ModTime())
	afterHandle, handleErr := file.Stat()
	afterPath, pathErr := regularFileInfo(path)
	closeErr := file.Close()
	if readErr != nil {
		return nil, authoritativeFingerprint{}, false,
			fmt.Errorf("read authoritative snapshot: %w", readErr)
	}
	if identityErr != nil {
		return nil, authoritativeFingerprint{}, false,
			fmt.Errorf("authenticate authoritative snapshot: %w", identityErr)
	}
	if handleErr != nil {
		return nil, authoritativeFingerprint{}, false,
			fmt.Errorf("restat authoritative snapshot: %w", handleErr)
	}
	if pathErr != nil {
		return nil, authoritativeFingerprint{}, false,
			fmt.Errorf("verify authoritative snapshot path: %w", pathErr)
	}
	if closeErr != nil {
		return nil, authoritativeFingerprint{}, false,
			fmt.Errorf("close authoritative snapshot: %w", closeErr)
	}
	if !os.SameFile(opened, afterHandle) ||
		!os.SameFile(opened, afterPath) ||
		afterHandle.Size() != opened.Size() ||
		afterPath.Size() != opened.Size() ||
		afterHandle.ModTime().UnixNano() != opened.ModTime().UnixNano() ||
		afterPath.ModTime().UnixNano() != opened.ModTime().UnixNano() {
		return nil, authoritativeFingerprint{}, false,
			errors.New("authoritative snapshot changed while it was being read")
	}
	if err := validateStoredEventsForContext(repoRoot, userID, events); err != nil {
		return nil, authoritativeFingerprint{}, false, err
	}
	return events, authoritativeFingerprint{
		Size:             identity.Fingerprint.Size,
		ModifiedUnixNano: identity.Fingerprint.ModifiedUnixNano,
		ContentDigest:    identity.Fingerprint.ContentDigest,
	}, true, nil
}

func sha256File(path string) (string, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func encodeEventsJSONL(events []model.Event) ([]byte, error) {
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return nil, errors.New("encode registry quarantine")
		}
	}
	return payload.Bytes(), nil
}

func quarantineRegistryBytes(repoRoot, sourceName string, payload []byte) error {
	directory := filepath.Join(localStoreDir(repoRoot), "quarantine")
	if err := validateDirectoryTree(repoRoot, directory); err != nil {
		return fmt.Errorf("validate registry quarantine directory: %w", err)
	}
	if err := ensureDirectoryDurableUnder(repoRoot, directory, 0o700); err != nil {
		return fmt.Errorf("create registry quarantine directory: %w", err)
	}
	safeName := strings.NewReplacer("/", "_", "\\", "_").Replace(sourceName)
	path := filepath.Join(directory, fmt.Sprintf("%s-%d", safeName, time.Now().UTC().UnixNano()))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create registry quarantine: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close empty registry quarantine: %w", err)
	}
	file, err = openProtectedRegularFile(repoRoot, path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open registry quarantine: %w", err)
	}
	if _, err = file.Write(payload); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("persist registry quarantine: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close registry quarantine: %w", closeErr)
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync registry quarantine directory: %w", err)
	}
	return nil
}

// appendNewLocalEvents appends only the events whose event_id is not already in
// any authoritative backup, then republishes the current user's registry. A
// global lookup matters because Git identity can change while a transcript is
// active; rereading that transcript must not import its old prompts again.
func appendNewLocalEvents(repoRoot, userID string, events []model.Event) (int, error) {
	added, _, err := appendNewLocalEventsDetailed(repoRoot, userID, events, nil)
	return added, err
}

// appendNewLocalEventsDetailed also returns current history IDs that were
// matched one-to-one to an older durable history-ID scheme. Recovery persists
// those aliases only after the append and store-prefix revalidation succeed, so
// a permanent transcript diagnostic cannot make the same migrated rows consume
// every bounded batch forever.
func appendNewLocalEventsDetailed(
	repoRoot,
	userID string,
	events []model.Event,
	reservedHistoryIDs map[string]bool,
) (int, map[string]string, error) {
	if userID == "" || len(events) == 0 {
		return 0, map[string]string{}, nil
	}
	if err := validateDirectoryTree(repoRoot, localStoreDir(repoRoot)); err != nil {
		return 0, nil, fmt.Errorf("validate local backup path: %w", err)
	}
	if err := ensureDirectoryDurableUnder(repoRoot, localStoreDir(repoRoot), 0o700); err != nil {
		return 0, nil, err
	}
	added := 0
	historyAliases := make(map[string]string)
	err := withFileLock(localStoreReconcileLockPath(repoRoot), localStoreLockTimeout, func() error {
		existing, err := readAllAuthoritativeEvents(repoRoot)
		if err != nil {
			return err
		}
		// Close the gap between the all-user scan and batching with a second,
		// atomic snapshot of the current user's append-only file. Its boundary
		// lets later batches consume every concurrent direct capture exactly
		// once without repeatedly decoding an arbitrary-size tail.
		currentSnapshot, concurrentBoundary, err := readAuthoritativeEventsSnapshot(repoRoot, userID)
		if err != nil {
			return err
		}
		existing, err = dedupeAndSortChecked(append(existing, currentSnapshot...))
		if err != nil {
			return err
		}
		seen := make(map[string]model.Event, len(existing))
		for _, event := range existing {
			seen[event.EventID] = event
		}
		fresh := make([]model.Event, 0, len(events))
		matchedHistoryPairs := correlateHistoryIDMigrationPairs(
			events,
			existing,
			reservedHistoryIDs,
		)
		matchedHistory := make(map[int]bool, len(matchedHistoryPairs))
		for eventIndex, existingIndex := range matchedHistoryPairs {
			matchedHistory[eventIndex] = true
			historyAliases[events[eventIndex].EventID] = existing[existingIndex].EventID
		}
		matchedDirect := correlateHistoryToDirectCaptures(events, existing, matchedHistory)
		for eventIndex, event := range events {
			if previous, duplicate := seen[event.EventID]; duplicate {
				if !sameLogicalStoredEvent(previous, event) {
					if isHistoryEventID(event.EventID) {
						// A redaction-policy or importer upgrade can transform an
						// old transcript row while retaining its stable history
						// ID. Preserve the authoritative copy, signal the drift,
						// and continue so later prompts in the file are not lost.
						recordLocalHealth(repoRoot, "history transform drift detected; authoritative event retained")
						continue
					}
					return fmt.Errorf("event_id %q has conflicting stored content", event.EventID)
				}
				continue
			}
			if matchedHistory[eventIndex] || matchedDirect[eventIndex] {
				seen[event.EventID] = event
				continue
			}
			seen[event.EventID] = event
			fresh = append(fresh, event)
		}
		if len(fresh) == 0 {
			return nil
		}
		const (
			historyBatchEvents = 25
			historyBatchBytes  = 4 * 1024 * 1024
		)
		concurrentDirect := make([]model.Event, 0)
		concurrentDirectSeen := make(map[string]struct{})
		consumedDirect := make(map[string]struct{})
		// A direct event that arrived late can legitimately correspond to a
		// history candidate already written by an earlier batch. Remember that
		// candidate so subsequent direct events cannot be paired to it again.
		consumedCandidates := make(map[int]bool)
		for offset := 0; offset < len(fresh); {
			end := offset
			encodedBytes := 0
			for end < len(fresh) && end-offset < historyBatchEvents {
				encoded, encodeErr := json.Marshal(fresh[end])
				if encodeErr != nil {
					return errors.New("encode history event for batching")
				}
				nextBytes := len(encoded) + 1
				if end > offset && encodedBytes+nextBytes > historyBatchBytes {
					break
				}
				encodedBytes += nextBytes
				end++
			}
			written := 0
			if err := withFileLock(localStoreCaptureLockPath(repoRoot, userID), localCaptureLockTimeout, func() error {
				delta, nextBoundary, err := readEventsFileFromOffset(
					authoritativePath(repoRoot, userID),
					concurrentBoundary,
				)
				if err != nil {
					return err
				}
				concurrentBoundary = nextBoundary
				for _, event := range delta {
					if !strings.HasPrefix(event.EventID, "hook-e-") {
						continue
					}
					if _, duplicate := concurrentDirectSeen[event.EventID]; duplicate {
						continue
					}
					concurrentDirectSeen[event.EventID] = struct{}{}
					concurrentDirect = append(concurrentDirect, event)
				}
				availableDirect := make([]model.Event, 0, len(concurrentDirect))
				for _, event := range concurrentDirect {
					if _, consumed := consumedDirect[event.EventID]; !consumed {
						availableDirect = append(availableDirect, event)
					}
				}
				matched := correlateHistoryToDirectCapturePairs(fresh, availableDirect, consumedCandidates)
				matchedThisRound := make(map[int]bool)
				for candidateIndex, directIndex := range matched {
					// Future candidates are deliberately left unreserved: a
					// closer direct capture may arrive before their batch.
					if candidateIndex >= end {
						continue
					}
					matchedThisRound[candidateIndex] = true
					consumedCandidates[candidateIndex] = true
					consumedDirect[availableDirect[directIndex].EventID] = struct{}{}
				}
				currentBatch := make([]model.Event, 0, end-offset)
				for candidateIndex := offset; candidateIndex < end; candidateIndex++ {
					if !matchedThisRound[candidateIndex] {
						currentBatch = append(currentBatch, fresh[candidateIndex])
					}
				}
				if len(currentBatch) == 0 {
					return nil
				}
				payload, err := encodeEventsJSONL(currentBatch)
				if err != nil {
					return err
				}
				recovered, err := appendEncodedEvents(
					repoRoot,
					authoritativePath(repoRoot, userID),
					payload,
				)
				if err != nil {
					return err
				}
				if recovered {
					recordLocalHealth(repoRoot, "repaired an incomplete trailing JSONL record during history import")
				}
				concurrentBoundary += int64(len(payload))
				written = len(currentBatch)
				return nil
			}); err != nil {
				return err
			}
			added += written
			offset = end
			if offset < len(fresh) {
				// File locks poll every 10 ms. Yield longer than one poll
				// interval so a waiting prompt hook can reliably win a window.
				time.Sleep(15 * time.Millisecond)
			}
		}
		return publishRegistryUnlocked(repoRoot, userID)
	})
	if err != nil {
		return added, nil, err
	}
	return added, historyAliases, nil
}

func readEventsFileFromOffset(path string, start int64) ([]model.Event, int64, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		if start != 0 {
			return nil, 0, errors.New("authoritative backup disappeared after snapshot")
		}
		return nil, 0, nil
	}
	if err != nil {
		return nil, start, fmt.Errorf("read authoritative delta: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, start, fmt.Errorf("stat authoritative delta: %w", err)
	}
	if start < 0 || start > info.Size() {
		return nil, start, errors.New("authoritative backup changed before delta read")
	}
	if start > 0 {
		var previous [1]byte
		if _, err := file.ReadAt(previous[:], start-1); err != nil {
			return nil, start, fmt.Errorf("validate authoritative delta boundary: %w", err)
		}
		if previous[0] != '\n' {
			return nil, start, errors.New("authoritative delta does not start on a JSONL boundary")
		}
	}
	if info.Size() > start {
		var final [1]byte
		if _, err := file.ReadAt(final[:], info.Size()-1); err != nil {
			return nil, start, fmt.Errorf("validate authoritative delta tail: %w", err)
		}
		if final[0] != '\n' {
			return nil, start, errors.New("authoritative delta has an incomplete trailing record")
		}
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return nil, start, fmt.Errorf("seek authoritative delta: %w", err)
	}
	var events []model.Event
	if err := forEachBoundedJSONLLine(file, 8*1024*1024, func(line []byte, oversized bool) error {
		if oversized {
			return errors.New("authoritative delta contains an oversized event")
		}
		event, decodeErr := decodeStoredEventLine(line)
		if decodeErr != nil {
			return errors.New("authoritative delta contains an invalid event")
		}
		events = append(events, event)
		return nil
	}); err != nil {
		return nil, start, fmt.Errorf("scan authoritative delta: %w", err)
	}
	return events, info.Size(), nil
}

func readAllAuthoritativeEvents(repoRoot string) ([]model.Event, error) {
	if err := validateDirectoryTree(repoRoot, localStoreDir(repoRoot)); err != nil {
		return nil, fmt.Errorf("validate local backup path: %w", err)
	}
	entries, err := os.ReadDir(localStoreDir(repoRoot))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read local backups: %w", err)
	}
	var all []model.Event
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), registryFileExt) {
			continue
		}
		userID := strings.TrimSuffix(entry.Name(), registryFileExt)
		events, err := readAuthoritativeEventsForPublish(repoRoot, userID)
		if err != nil {
			return nil, err
		}
		all = append(all, events...)
	}
	return dedupeAndSortChecked(all)
}

// readAuthoritativeRecoverySnapshot returns prompt-only events and full-file
// fingerprints for the exact capture-lock-protected bytes that produced them.
// Recovery can safely pre-deduplicate against this snapshot only if the same
// prefixes still exist before provider scan state is committed.
func readAuthoritativeRecoverySnapshot(
	repoRoot string,
) ([]model.Event, map[string]authoritativeFingerprint, error) {
	if err := validateDirectoryTree(repoRoot, localStoreDir(repoRoot)); err != nil {
		return nil, nil, fmt.Errorf("validate local backup path: %w", err)
	}
	entries, err := os.ReadDir(localStoreDir(repoRoot))
	if errors.Is(err, os.ErrNotExist) {
		return nil, map[string]authoritativeFingerprint{}, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read local backups: %w", err)
	}
	var all []model.Event
	fingerprints := make(map[string]authoritativeFingerprint)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), registryFileExt) {
			continue
		}
		name := entry.Name()
		userID := strings.TrimSuffix(name, registryFileExt)
		path := filepath.Join(localStoreDir(repoRoot), name)
		var snapshot []model.Event
		var fingerprint authoritativeFingerprint
		present := false
		lockErr := withFileLock(
			localStoreCaptureLockPath(repoRoot, userID),
			localCaptureLockTimeout,
			func() error {
				current, boundary, currentFingerprint, currentPresent, err :=
					readAuthoritativeEventsSnapshotUnlocked(
						repoRoot,
						userID,
						path,
					)
				if err != nil {
					return err
				}
				if !currentPresent {
					return nil
				}
				snapshot = current
				fingerprint = currentFingerprint
				if fingerprint.Size != boundary {
					return errors.New("authoritative snapshot boundary is inconsistent")
				}
				present = true
				return nil
			},
		)
		if lockErr != nil {
			return nil, nil, fmt.Errorf("snapshot authoritative backup %s: %w", name, lockErr)
		}
		if present {
			all = append(all, snapshot...)
			fingerprints[name] = fingerprint
		}
	}
	all, err = dedupeAndSortChecked(all)
	if err != nil {
		return nil, nil, err
	}
	return all, fingerprints, nil
}

func appendEvent(authorityRoot, path string, event model.Event) (bool, error) {
	line, err := json.Marshal(event)
	if err != nil {
		return false, errors.New("encode local event")
	}
	return appendEncodedEvents(authorityRoot, path, append(line, '\n'))
}

func appendEncodedEvents(authorityRoot, path string, payload []byte) (bool, error) {
	if len(payload) == 0 || payload[len(payload)-1] != '\n' {
		return false, errors.New("encoded local events must end with a newline")
	}
	recovered, err := repairTrailingJSONL(authorityRoot, path)
	if err != nil {
		return false, err
	}
	info, statErr := os.Lstat(path)
	newFile := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !newFile {
		return recovered, fmt.Errorf("inspect local backup before append: %w", statErr)
	}
	if !newFile && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return recovered, errors.New("local backup is not a regular file")
	}
	if newFile {
		created, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			return recovered, fmt.Errorf("create local backup: %w", createErr)
		}
		if closeErr := created.Close(); closeErr != nil {
			return recovered, fmt.Errorf("close new local backup: %w", closeErr)
		}
	}
	if newFile {
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return recovered, fmt.Errorf("sync new local backup directory: %w", err)
		}
	}
	// Apply confidentiality controls and bind the data handle to that exact
	// protected object before writing any prompt bytes.
	f, err := openProtectedRegularFile(authorityRoot, path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return recovered, fmt.Errorf("open local backup: %w", err)
	}
	if _, err = f.Write(payload); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return recovered, fmt.Errorf("persist local backup: %w", err)
	}
	if closeErr != nil {
		return recovered, fmt.Errorf("close local backup: %w", closeErr)
	}
	return recovered, nil
}

// repairTrailingJSONL handles the only corruption shape an interrupted append
// can create: an incomplete final line. A complete JSON object merely missing
// its newline is preserved; an invalid tail is quarantined before truncation.
func repairTrailingJSONL(authorityRoot, path string) (recovered bool, resultErr error) {
	file, err := openProtectedRegularFile(authorityRoot, path, os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect local backup tail: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && resultErr == nil {
			resultErr = fmt.Errorf("close repaired JSONL: %w", closeErr)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect local backup size: %w", err)
	}
	if info.Size() == 0 {
		return false, nil
	}
	var finalByte [1]byte
	if _, err := file.ReadAt(finalByte[:], info.Size()-1); err != nil {
		return false, fmt.Errorf("inspect local backup final byte: %w", err)
	}
	if finalByte[0] == '\n' {
		return false, nil
	}

	// A normal event is far smaller than this. Bound in-memory recovery while
	// still locating and hashing an arbitrarily large incomplete final record.
	const maxRecoverableJSONLRecord = 8 * 1024 * 1024
	tailStart, err := findJSONLTailStart(file, info.Size())
	if err != nil {
		return false, err
	}
	tailLength := info.Size() - tailStart
	if tailLength <= maxRecoverableJSONLRecord {
		data := make([]byte, tailLength)
		if _, err := file.ReadAt(data, tailStart); err != nil {
			return false, fmt.Errorf("read local backup tail: %w", err)
		}
		tail := bytes.TrimSpace(data)
		if len(tail) > 0 && json.Valid(tail) {
			if _, err := file.Seek(0, io.SeekEnd); err != nil {
				return false, fmt.Errorf("seek to repair missing JSONL newline: %w", err)
			}
			_, writeErr := file.Write([]byte{'\n'})
			if writeErr == nil {
				writeErr = file.Sync()
			}
			if writeErr != nil {
				return false, fmt.Errorf("repair missing JSONL newline: %w", writeErr)
			}
			return true, nil
		}
	}

	quarantine := fmt.Sprintf("%s.corrupt-%d", path, time.Now().UTC().UnixNano())
	quarantineFile, err := os.OpenFile(quarantine, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false, fmt.Errorf("create incomplete JSONL quarantine: %w", err)
	}
	if err := quarantineFile.Close(); err != nil {
		return false, fmt.Errorf("close empty incomplete JSONL quarantine: %w", err)
	}
	quarantineFile, err = openProtectedRegularFile(
		authorityRoot,
		quarantine,
		os.O_WRONLY|os.O_TRUNC,
		0o600,
	)
	if err != nil {
		return false, fmt.Errorf("open incomplete JSONL quarantine: %w", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.NewSectionReader(file, tailStart, tailLength)); err != nil {
		_ = quarantineFile.Close()
		return false, fmt.Errorf("digest incomplete JSONL tail: %w", err)
	}
	evidence := []byte(fmt.Sprintf(
		"source=%s\nbytes=%d\nsha256=%s\n",
		filepath.Base(path), tailLength, hex.EncodeToString(hasher.Sum(nil)),
	))
	// An invalid tail can be tampered to contain fields outside the prompt-only
	// contract. Keep only length and digest evidence, never the raw fragment.
	if _, err = quarantineFile.Write(evidence); err == nil {
		err = quarantineFile.Sync()
	}
	closeErr := quarantineFile.Close()
	if err != nil {
		return false, fmt.Errorf("persist incomplete JSONL quarantine: %w", err)
	}
	if closeErr != nil {
		return false, fmt.Errorf("close incomplete JSONL quarantine: %w", closeErr)
	}
	if err := syncDirectory(filepath.Dir(quarantine)); err != nil {
		return false, fmt.Errorf("sync incomplete JSONL quarantine directory: %w", err)
	}
	if err = file.Truncate(tailStart); err == nil {
		err = file.Sync()
	}
	if err != nil {
		return false, fmt.Errorf("truncate incomplete JSONL tail: %w", err)
	}
	return true, nil
}

func findJSONLTailStart(file *os.File, size int64) (int64, error) {
	const searchBlock = 64 * 1024
	buffer := make([]byte, searchBlock)
	for end := size; end > 0; {
		start := end - searchBlock
		if start < 0 {
			start = 0
		}
		length := int(end - start)
		if _, err := file.ReadAt(buffer[:length], start); err != nil {
			return 0, fmt.Errorf("search local backup tail boundary: %w", err)
		}
		if index := bytes.LastIndexByte(buffer[:length], '\n'); index >= 0 {
			return start + int64(index) + 1, nil
		}
		end = start
	}
	return 0, nil
}

func readEventsFile(path string) ([]model.Event, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	defer file.Close()
	var events []model.Event
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if len(scanner.Bytes()) == 0 {
			continue
		}
		event, err := decodeStoredEventLine(scanner.Bytes())
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid JSON on line %d", filepath.Base(path), lineNumber)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", filepath.Base(path), err)
	}
	return events, nil
}

func readValidEventsFile(path string) ([]model.Event, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("read registry for strict salvage: %w", err)
	}
	defer file.Close()
	var events []model.Event
	if err := forEachBoundedJSONLLine(file, 8*1024*1024, func(line []byte, oversized bool) error {
		if oversized || len(line) == 0 {
			return nil
		}
		event, decodeErr := decodeStoredEventLine(line)
		if decodeErr == nil {
			events = append(events, event)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("scan registry for strict salvage: %w", err)
	}
	return dedupeAndSortChecked(events)
}

func forEachBoundedJSONLLine(source io.Reader, limit int, visit func([]byte, bool) error) error {
	reader := bufio.NewReaderSize(source, 64*1024)
	line := make([]byte, 0, 64*1024)
	oversized := false
	for {
		fragment, readErr := reader.ReadSlice('\n')
		if !oversized {
			if len(line)+len(fragment) > limit {
				oversized = true
				line = line[:0]
			} else {
				line = append(line, fragment...)
			}
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if oversized {
			if err := visit(nil, true); err != nil {
				return err
			}
		} else {
			line = bytes.TrimRight(line, "\r\n")
			if len(line) > 0 {
				if err := visit(line, false); err != nil {
					return err
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		line = line[:0]
		oversized = false
	}
}

func decodeStoredEventLine(line []byte) (model.Event, error) {
	if err := validateUniqueJSONKeys(line); err != nil {
		return model.Event{}, errors.New("ambiguous or invalid stored event JSON")
	}
	var event model.Event
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return model.Event{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return model.Event{}, errors.New("multiple JSON values")
	}
	if err := validateStoredEvent(event); err != nil {
		return model.Event{}, err
	}
	return event, nil
}

func validateStoredEvent(event model.Event) error {
	switch {
	case strings.TrimSpace(event.EventID) == "":
		return errors.New("event_id is empty")
	case len(event.EventID) > 255 || !utf8.ValidString(event.EventID):
		return errors.New("event_id is oversized or invalid UTF-8")
	case event.Timestamp.IsZero():
		return errors.New("timestamp is empty")
	case strings.TrimSpace(event.UserID) == "":
		return errors.New("user_id is empty")
	case len(event.UserID) > 255 || !utf8.ValidString(event.UserID):
		return errors.New("user_id is oversized or invalid UTF-8")
	case strings.TrimSpace(event.UserEmail) == "" || len(event.UserEmail) > 320 || !utf8.ValidString(event.UserEmail):
		return errors.New("user_email is empty, oversized, or invalid UTF-8")
	case !verifiedPromptAdapter(event.Tool):
		return errors.New("tool is not a verified prompt adapter")
	case strings.TrimSpace(event.RepositoryName) == "" || len(event.RepositoryName) > 255 ||
		!utf8.ValidString(event.RepositoryName):
		return errors.New("repository_name is empty, oversized, or invalid UTF-8")
	case strings.TrimSpace(event.RepositoryRemote) == "" || len(event.RepositoryRemote) > 2048 ||
		!utf8.ValidString(event.RepositoryRemote):
		return errors.New("repository_remote is empty, oversized, or invalid UTF-8")
	case len(event.Branch) > 1024 || !utf8.ValidString(event.Branch):
		return errors.New("branch is oversized or invalid UTF-8")
	case len(event.CommitHash) > 255 || !utf8.ValidString(event.CommitHash):
		return errors.New("commit_hash is oversized or invalid UTF-8")
	case strings.TrimSpace(event.SessionID) == "":
		return errors.New("session_id is empty")
	case len(event.SessionID) > 4096 || !utf8.ValidString(event.SessionID):
		return errors.New("session_id is oversized or invalid UTF-8")
	case strings.TrimSpace(event.Prompt) == "":
		return errors.New("prompt is empty")
	case len(event.Prompt) > maxQueuedPromptBytes || !utf8.ValidString(event.Prompt):
		return errors.New("prompt is oversized or invalid UTF-8")
	default:
		return nil
	}
}

type storedEventContext struct {
	projectName            string
	repositoryRemote       string
	legacyRepositoryRemote string
	allowLegacyMigration   bool
}

func loadStoredEventContext(repoRoot string) (storedEventContext, bool, error) {
	_, err := loadProjectConfig(repoRoot)
	if err != nil {
		// Low-level unit tests and strict file utilities can operate without a
		// project fixture. Production entry points discover and validate the
		// repository before reaching this context check.
		return storedEventContext{}, false, nil
	}
	repo, err := DiscoverRepository(repoRoot)
	if err != nil {
		return storedEventContext{}, false, fmt.Errorf("discover stored-event repository context: %w", err)
	}
	marker := filepath.Join(localStoreDir(repoRoot), repositoryIdentityFile)
	markerInfo, markerErr := os.Lstat(marker)
	allowLegacyMigration := errors.Is(markerErr, os.ErrNotExist)
	if markerErr != nil && !allowLegacyMigration {
		return storedEventContext{}, false, fmt.Errorf("inspect repository identity marker: %w", markerErr)
	}
	if markerErr == nil &&
		(markerInfo.Mode()&os.ModeSymlink != 0 || !markerInfo.Mode().IsRegular()) {
		return storedEventContext{}, false, errors.New("repository identity marker is not a regular file")
	}
	return storedEventContext{
		projectName:            repo.Name,
		repositoryRemote:       stableLocalRepositoryRemote(repo.Project),
		legacyRepositoryRemote: repo.Remote,
		allowLegacyMigration:   allowLegacyMigration,
	}, true, nil
}

// verifiedPromptAdapter is the allow-list of tools whose prompts this build
// knows how to capture. It gates storage, so a name that is merely present in
// project.json cannot put rows in the register: the build must actually
// implement the adapter.
func verifiedPromptAdapter(tool string) bool {
	switch tool {
	case model.ToolClaudeCode, model.ToolCodex, model.ToolCopilotCLI, model.ToolAntigravity:
		return true
	default:
		return false
	}
}

func validateStoredEventContext(context storedEventContext, expectedUserID string, event model.Event) error {
	if event.UserID != expectedUserID {
		return errors.New("stored event user_id does not match its per-user file")
	}
	if event.RepositoryName != context.projectName ||
		event.RepositoryRemote != context.repositoryRemote {
		return errors.New("stored event belongs to a different project")
	}
	return nil
}

func normalizeStoredEventsForContext(
	repoRoot, expectedUserID string,
	events []model.Event,
) ([]model.Event, bool, error) {
	context, available, err := loadStoredEventContext(repoRoot)
	if err != nil {
		return nil, false, err
	}
	if !available {
		return events, false, nil
	}
	normalized := append([]model.Event(nil), events...)
	changed := false
	for index := range normalized {
		event := &normalized[index]
		if event.UserID != expectedUserID {
			return nil, false, errors.New("stored event user_id does not match its per-user file")
		}
		if event.RepositoryName != context.projectName {
			return nil, false, errors.New("stored event belongs to a different project")
		}
		switch event.RepositoryRemote {
		case context.repositoryRemote:
		case context.legacyRepositoryRemote:
			event.RepositoryRemote = context.repositoryRemote
			changed = true
		default:
			if !context.allowLegacyMigration {
				return nil, false, errors.New("stored event belongs to a different project")
			}
			event.RepositoryRemote = context.repositoryRemote
			changed = true
		}
	}
	return normalized, changed, nil
}

func validateStoredEventsForContext(repoRoot, expectedUserID string, events []model.Event) error {
	_, changed, err := normalizeStoredEventsForContext(repoRoot, expectedUserID, events)
	if err != nil {
		return err
	}
	if changed {
		return errors.New("stored event uses a legacy repository identity and requires migration")
	}
	return nil
}

func filterStoredEventsForContext(repoRoot, expectedUserID string, events []model.Event) ([]model.Event, bool, error) {
	context, available, err := loadStoredEventContext(repoRoot)
	if err != nil {
		return nil, false, err
	}
	if !available {
		return events, false, nil
	}
	valid := make([]model.Event, 0, len(events))
	invalid := false
	for _, original := range events {
		event := original
		if event.UserID != expectedUserID || event.RepositoryName != context.projectName {
			invalid = true
			continue
		}
		switch event.RepositoryRemote {
		case context.repositoryRemote:
		case context.legacyRepositoryRemote:
			event.RepositoryRemote = context.repositoryRemote
			invalid = true
		default:
			if !context.allowLegacyMigration {
				invalid = true
				continue
			}
			event.RepositoryRemote = context.repositoryRemote
			invalid = true
		}
		valid = append(valid, event)
	}
	return valid, invalid, nil
}

func writeEventsFileAtomic(path string, events []model.Event) error {
	return writeEventsFileAtomicMode("", path, events, false)
}

func writePrivateEventsFileAtomic(authorityRoot, path string, events []model.Event) error {
	return writeEventsFileAtomicMode(authorityRoot, path, events, true)
}

func writeEventsFileAtomicMode(authorityRoot, path string, events []model.Event, private bool) error {
	dir := filepath.Dir(path)
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
			return errors.New("refuse to replace a non-regular registry file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect registry destination: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".registry-*.tmp")
	if err != nil {
		return fmt.Errorf("create registry rewrite: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close empty registry rewrite: %w", err)
	}
	if private {
		tmp, err = openProtectedRegularFile(
			authorityRoot,
			tmpName,
			os.O_TRUNC|os.O_WRONLY,
			0o600,
		)
	} else if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("set registry permissions: %w", err)
	}
	if !private {
		tmp, err = openExistingRegularFile(tmpName, os.O_TRUNC|os.O_WRONLY, 0o600)
	}
	if err != nil {
		return fmt.Errorf("open registry rewrite: %w", err)
	}
	writer := bufio.NewWriter(tmp)
	encoder := json.NewEncoder(writer)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("write registry: %w", err)
		}
	}
	persistErr := writer.Flush()
	if persistErr == nil {
		persistErr = tmp.Sync()
	}
	closeErr := tmp.Close()
	if persistErr != nil {
		return fmt.Errorf("persist registry rewrite: %w", persistErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close registry rewrite: %w", closeErr)
	}
	if err := replaceFile(tmpName, path); err != nil {
		return fmt.Errorf("replace registry: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync registry directory: %w", err)
	}
	return nil
}

// dedupeAndSort collapses duplicate event_ids (a union merge can duplicate a
// line) and orders events chronologically, then by event_id for stability.
func dedupeAndSort(events []model.Event) []model.Event {
	seen := make(map[string]struct{}, len(events))
	unique := make([]model.Event, 0, len(events))
	for _, event := range events {
		if event.EventID == "" {
			continue
		}
		if _, duplicate := seen[event.EventID]; duplicate {
			continue
		}
		seen[event.EventID] = struct{}{}
		unique = append(unique, event)
	}
	sort.SliceStable(unique, func(i, j int) bool {
		if unique[i].Timestamp.Equal(unique[j].Timestamp) {
			return unique[i].EventID < unique[j].EventID
		}
		return unique[i].Timestamp.Before(unique[j].Timestamp)
	})
	return unique
}

func dedupeAndSortChecked(events []model.Event) ([]model.Event, error) {
	seen := make(map[string]model.Event, len(events))
	for _, event := range events {
		if event.EventID == "" {
			continue
		}
		if previous, duplicate := seen[event.EventID]; duplicate && !sameLogicalStoredEvent(previous, event) {
			return nil, fmt.Errorf("event_id %q has conflicting payloads", event.EventID)
		}
		seen[event.EventID] = event
	}
	return dedupeAndSort(events), nil
}

// Scanner IDs are derived from transcript session+index. Identity, branch and
// commit describe the machine at import time and may legitimately change when
// the same history row is encountered again. The prompt-bearing fields must
// still match exactly; otherwise the collision is treated as corruption.
func sameLogicalStoredEvent(previous, candidate model.Event) bool {
	if previous == candidate {
		return true
	}
	if previous.EventID != candidate.EventID {
		return false
	}
	if strings.HasPrefix(previous.EventID, "hook-e-") {
		return previous.Tool == candidate.Tool &&
			previous.SessionID == candidate.SessionID &&
			previous.Prompt == candidate.Prompt
	}
	if !isHistoryEventID(previous.EventID) || !isHistoryEventID(candidate.EventID) {
		return false
	}
	return previous.Timestamp.Equal(candidate.Timestamp) &&
		previous.Tool == candidate.Tool &&
		previous.SessionID == candidate.SessionID &&
		previous.Prompt == candidate.Prompt
}

// historyEventIDPrefixes is the single registry of recovered-history id
// prefixes. Every scanner must appear here: an id that is not recognised as
// history is treated as a DIRECT capture by the dedupe machinery, which then
// correlates it against itself and re-quarantines the scan state on every pass.
// Adding an adapter and forgetting its prefix is a silent, expensive mistake,
// so the list lives in one place and a test walks it.
var historyEventIDPrefixes = []string{
	"codex-h-",
	"claude-h-",
	"copilot-h-",
	"antigravity-h-",
}

func isHistoryEventID(eventID string) bool {
	for _, prefix := range historyEventIDPrefixes {
		if strings.HasPrefix(eventID, prefix) {
			return true
		}
	}
	return false
}

type eventMatch struct {
	candidate int
	existing  int
	delta     time.Duration
}

// correlateHistoryIDMigration keeps rows written by older scanner ID schemes
// without duplicating them after an upgrade. Exact prompt-bearing fields and
// timestamps are matched one-to-one.
func correlateHistoryIDMigration(candidates, existing []model.Event) map[int]bool {
	selected := correlateHistoryIDMigrationPairs(candidates, existing, nil)
	matched := make(map[int]bool, len(selected))
	for candidateIndex := range selected {
		matched[candidateIndex] = true
	}
	return matched
}

func correlateHistoryIDMigrationPairs(
	candidates,
	existing []model.Event,
	reservedHistoryIDs map[string]bool,
) map[int]int {
	candidateIDs := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if isHistoryEventID(candidate.EventID) {
			candidateIDs[candidate.EventID] = struct{}{}
		}
	}
	reservedExisting := make(map[int]bool)
	for existingIndex, current := range existing {
		_, exactCandidateExists := candidateIDs[current.EventID]
		if exactCandidateExists || reservedHistoryIDs[current.EventID] {
			reservedExisting[existingIndex] = true
		}
	}
	pairs := make([]eventMatch, 0)
	for candidateIndex, candidate := range candidates {
		if !isHistoryEventID(candidate.EventID) {
			continue
		}
		for existingIndex, current := range existing {
			if reservedExisting[existingIndex] ||
				current.EventID == candidate.EventID ||
				!isHistoryEventID(current.EventID) {
				continue
			}
			if current.Timestamp.Equal(candidate.Timestamp) &&
				current.Tool == candidate.Tool &&
				current.SessionID == candidate.SessionID &&
				current.Prompt == candidate.Prompt {
				pairs = append(pairs, eventMatch{candidate: candidateIndex, existing: existingIndex})
			}
		}
	}
	return selectOneToOneMatchPairs(pairs, nil)
}

// correlateHistoryToDirectCaptures only pairs events with the same timestamp.
// A fuzzy window can incorrectly consume a genuine repeated prompt when the
// provider transcript omits the turn that was captured directly.
func correlateHistoryToDirectCaptures(candidates, existing []model.Event, excluded map[int]bool) map[int]bool {
	selected := correlateHistoryToDirectCapturePairs(candidates, existing, excluded)
	matched := make(map[int]bool, len(selected))
	for candidate := range selected {
		matched[candidate] = true
	}
	return matched
}

func correlateHistoryToDirectCapturePairs(candidates, existing []model.Event, excluded map[int]bool) map[int]int {
	pairs := make([]eventMatch, 0)
	for candidateIndex, candidate := range candidates {
		if excluded[candidateIndex] || !isHistoryEventID(candidate.EventID) {
			continue
		}
		for existingIndex, current := range existing {
			if isHistoryEventID(current.EventID) ||
				current.Tool != candidate.Tool ||
				current.SessionID != candidate.SessionID ||
				current.Prompt != candidate.Prompt ||
				!current.Timestamp.Equal(candidate.Timestamp) {
				continue
			}
			pairs = append(pairs, eventMatch{
				candidate: candidateIndex,
				existing:  existingIndex,
			})
		}
	}
	return selectOneToOneMatchPairs(pairs, excluded)
}

func selectOneToOneMatches(pairs []eventMatch, excluded map[int]bool) map[int]bool {
	selected := selectOneToOneMatchPairs(pairs, excluded)
	matched := make(map[int]bool, len(selected))
	for candidate := range selected {
		matched[candidate] = true
	}
	return matched
}

func selectOneToOneMatchPairs(pairs []eventMatch, excluded map[int]bool) map[int]int {
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].delta != pairs[j].delta {
			return pairs[i].delta < pairs[j].delta
		}
		if pairs[i].candidate != pairs[j].candidate {
			return pairs[i].candidate < pairs[j].candidate
		}
		return pairs[i].existing < pairs[j].existing
	})
	matchedCandidates := make(map[int]int)
	matchedExisting := make(map[int]bool)
	for _, pair := range pairs {
		if excluded[pair.candidate] || matchedExisting[pair.existing] {
			continue
		}
		if _, matched := matchedCandidates[pair.candidate]; matched {
			continue
		}
		matchedCandidates[pair.candidate] = pair.existing
		matchedExisting[pair.existing] = true
	}
	return matchedCandidates
}

// readRegistryEvents returns the deduplicated union of every user's committed
// registry file. This is what an administrator reviews after pulling the repo.
func readRegistryEvents(repoRoot string) ([]model.Event, error) {
	if err := validateDirectoryTree(repoRoot, registryDir(repoRoot)); err != nil {
		return nil, fmt.Errorf("validate prompt registry path: %w", err)
	}
	entries, err := os.ReadDir(registryDir(repoRoot))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read registry directory: %w", err)
	}
	var all []model.Event
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), registryFileExt) {
			continue
		}
		userID := strings.TrimSuffix(entry.Name(), registryFileExt)
		events, err := readEventsFile(filepath.Join(registryDir(repoRoot), entry.Name()))
		if err != nil {
			return nil, err
		}
		if err := validateStoredEventsForContext(repoRoot, userID, events); err != nil {
			return nil, fmt.Errorf("%s contains an out-of-scope event: %w", entry.Name(), err)
		}
		all = append(all, events...)
	}
	return dedupeAndSortChecked(all)
}

// LocalLog renders the committed registry in the terminal as
// user -> chat -> prompts, mirroring the HTML administrator report.
func LocalLog(out io.Writer, start string) error {
	repo, err := DiscoverRepository(start)
	if err != nil {
		return err
	}
	if !repo.Project.LocalStore {
		_, err := fmt.Fprintln(out, "El registro local demo no está activo (local_store: false en .devtools/project.json).")
		return err
	}
	// Viewing is a request to see prompts, so recover from the local provider
	// transcripts first — the Codex hook may never have run on a fresh clone.
	recoverForViewingBestEffort(repo)
	// Keep direct-capture delivery available without performing session
	// activation.
	if hookErr := ensurePreCommitHook(repo.Root); hookErr != nil {
		recordLocalHealth(repo.Root, "log warning: pre-commit delivery hook is unavailable")
		if _, writeErr := fmt.Fprintln(out, "Advertencia: el hook de entrega pre-commit no está activo."); writeErr != nil {
			return writeErr
		}
	}
	if err := publishAllRegistryBackups(repo.Root); err != nil {
		return fmt.Errorf("publish prompt registry: %w", err)
	}
	events, err := readRegistryEvents(repo.Root)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Registro de prompts (modo local)\nCarpeta: %s\n\n", registryDir(repo.Root)); err != nil {
		return err
	}
	if len(events) == 0 {
		_, err := fmt.Fprintln(out, "Todavía no hay prompts. Envía uno desde Claude Code, Codex o Copilot CLI dentro de este repositorio.")
		return err
	}
	return printLocalHierarchy(out, events)
}

func printLocalHierarchy(out io.Writer, events []model.Event) error {
	byUser := groupBy(events, func(e model.Event) string { return e.UserEmail })
	chats := map[string]struct{}{}
	for _, e := range events {
		chats[e.UserEmail+"\n"+e.SessionID] = struct{}{}
	}
	for _, email := range sortedKeys(byUser) {
		if _, err := fmt.Fprintf(out, "Usuario: %s\n", email); err != nil {
			return err
		}
		bySession := groupBy(byUser[email], func(e model.Event) string { return e.SessionID })
		for _, session := range sortedKeys(bySession) {
			prompts := dedupeAndSort(bySession[session])
			tool := prompts[0].Tool
			if _, err := fmt.Fprintf(out, "  Chat: %s  (herramienta: %s)\n", session, tool); err != nil {
				return err
			}
			for _, event := range prompts {
				stamp := event.Timestamp.UTC().Format("2006-01-02 15:04:05")
				if _, err := fmt.Fprintf(out, "    [%s UTC] %s\n", stamp, singleLine(event.Prompt)); err != nil {
					return err
				}
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(out, "Resumen: %d prompt(s), %d usuario(s), %d chat(s).\n", len(events), len(byUser), len(chats))
	return err
}

func groupBy(events []model.Event, key func(model.Event) string) map[string][]model.Event {
	groups := map[string][]model.Event{}
	for _, event := range events {
		k := key(event)
		groups[k] = append(groups[k], event)
	}
	return groups
}

func sortedKeys(groups map[string][]model.Event) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// singleLine keeps a multi-line prompt readable on one row of the listing.
func singleLine(value string) string {
	replacer := strings.NewReplacer("\r\n", " ⏎ ", "\n", " ⏎ ", "\r", " ⏎ ")
	value = replacer.Replace(value)
	var safe strings.Builder
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			_, _ = fmt.Fprintf(&safe, "\\u%04X", character)
			continue
		}
		safe.WriteRune(character)
	}
	return safe.String()
}
