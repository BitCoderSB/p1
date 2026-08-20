package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/acme/prompt-audit-template/internal/model"
)

func requireFileSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links are unavailable for this test: %v", err)
	}
}

func TestTrustedDirectoryTreeRejectsSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatalf("create synthetic outside directory: %v", err)
	}
	link := filepath.Join(root, "linked")
	requireFileSymlink(t, outside, link)

	if err := validateDirectoryTree(root, filepath.Join(link, "prompt-storage")); err == nil {
		t.Fatal("trusted directory validation accepted a symbolic-link ancestor")
	}
	if _, err := os.Lstat(filepath.Join(outside, "prompt-storage")); !os.IsNotExist(err) {
		t.Fatalf("symbolic-link target was mutated: %v", err)
	}
}

func TestTrustedDirectoryTreeAllowsAliasAtTrustedBoundary(t *testing.T) {
	canonical := filepath.Join(t.TempDir(), "canonical-repository")
	child := filepath.Join(canonical, ".devtools")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatalf("create canonical repository fixture: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "repository-alias")
	requireFileSymlink(t, canonical, alias)

	if err := validateDirectoryTree(alias, filepath.Join(alias, ".devtools")); err != nil {
		t.Fatalf("trusted boundary alias was rejected: %v", err)
	}
}

func TestEnsureDirectoryDurableAllowsCanonicalSystemStyleAlias(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "canonical")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatalf("create synthetic canonical directory: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "system-alias")
	requireFileSymlink(t, outside, alias)
	requested := filepath.Join(alias, "prompt-storage")

	if err := ensureDirectoryDurable(requested, 0o700); err != nil {
		t.Fatalf("ensureDirectoryDurable rejected a canonical system-style alias: %v", err)
	}
	info, err := os.Lstat(filepath.Join(outside, "prompt-storage"))
	if err != nil || !info.IsDir() {
		t.Fatalf("canonical directory was not created: %v", err)
	}
}

func TestWriteLocalEventRejectsSymlinkAuthoritativeFile(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	discovered, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatalf("discover synthetic repository: %v", err)
	}
	const email = "symlink-test@example.invalid"
	userID := localUserID(email)
	event := sampleEvent("symlink-authoritative-event", "synthetic prompt that must not follow a link")
	event.UserID = userID
	event.UserEmail = email
	event.RepositoryName = discovered.Name
	event.RepositoryRemote = discovered.Remote

	if err := ensureDirectoryDurable(localStoreDir(repository.Root), 0o700); err != nil {
		t.Fatalf("create local-store fixture: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	sentinel := []byte("outside sentinel\n")
	if err := os.WriteFile(outside, sentinel, 0o600); err != nil {
		t.Fatalf("write synthetic outside file: %v", err)
	}
	requireFileSymlink(t, outside, authoritativePath(repository.Root, userID))

	if err := writeLocalEvent(repository.Root, event); err == nil {
		t.Fatal("writeLocalEvent accepted a symbolic-link authoritative file")
	}
	after, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read synthetic outside file: %v", err)
	}
	if !bytes.Equal(after, sentinel) {
		t.Fatal("authoritative-file symlink target was modified")
	}
}

func TestQueueEnqueueRejectsSymlinkEventFile(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatalf("OpenQueue() error = %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside-queue.jsonl")
	sentinel := []byte("outside queue sentinel\n")
	if err := os.WriteFile(outside, sentinel, 0o600); err != nil {
		t.Fatalf("write synthetic outside queue: %v", err)
	}
	requireFileSymlink(t, outside, queue.path)

	if err := queue.Enqueue(sampleEvent("symlink-queue-event", "synthetic queued prompt")); err == nil {
		t.Fatal("Queue.Enqueue accepted a symbolic-link event file")
	}
	after, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read synthetic outside queue: %v", err)
	}
	if !bytes.Equal(after, sentinel) {
		t.Fatal("queue symlink target was modified")
	}
}

func TestRecordLocalHealthRejectsSymlinkFile(t *testing.T) {
	root := t.TempDir()
	directory := localStoreDir(root)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-health.log")
	sentinel := []byte("outside health sentinel\n")
	if err := os.WriteFile(outside, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	requireFileSymlink(t, outside, filepath.Join(directory, healthLogFileName))

	recordLocalHealth(root, "generic synthetic health message")
	after, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, sentinel) {
		t.Fatal("health symlink target was modified")
	}
}

func TestWriteReportAtomicRejectsSymlinkDestination(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".devtools"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-report.html")
	sentinel := []byte("outside report sentinel\n")
	if err := os.WriteFile(outside, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, ".devtools", reportFileName)
	requireFileSymlink(t, outside, destination)

	err := writeReportAtomic(root, destination, []byte("<html>synthetic report</html>"))
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("writeReportAtomic symlink error = %v, want unsafe-destination rejection", err)
	}
	after, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, sentinel) {
		t.Fatal("report symlink target was modified")
	}
}

func TestQuarantineRegistryRejectsSymlinkDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(localStoreDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	link := filepath.Join(localStoreDir(root), "quarantine")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("directory symbolic links are unavailable for this test: %v", err)
	}
	if err := quarantineRegistryBytes(root, "synthetic.digest", []byte("sha256=synthetic\n")); err == nil {
		t.Fatal("quarantineRegistryBytes accepted a symbolic-link directory")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("registry quarantine wrote outside the trusted repository tree")
	}
}
