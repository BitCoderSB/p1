package audit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireStorageSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links are unavailable for this test: %v", err)
	}
}

func TestWithFileLockRejectsSymlinkWithoutRunningCallback(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside.lock")
	sentinel := []byte("outside lock sentinel\n")
	if err := os.WriteFile(target, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(directory, "events.lock")
	requireStorageSymlink(t, target, lockPath)

	called := false
	err := withFileLock(lockPath, time.Second, func() error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("withFileLock accepted a symbolic-link lock file")
	}
	if called {
		t.Fatal("withFileLock ran its callback through a symbolic-link lock")
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, sentinel) {
		t.Fatal("lock symlink target was modified")
	}
}

func TestWithFileLockVerifiesOpenedFileIdentity(t *testing.T) {
	directory := t.TempDir()
	expected := filepath.Join(directory, "expected.lock")
	different := filepath.Join(directory, "different.lock")
	if err := os.WriteFile(expected, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(different, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(different, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if err := verifyOpenedRegularFile(expected, file); err == nil {
		t.Fatal("file identity verification accepted a different opened inode")
	}
}

func TestWithFileLockCreatesAndReusesRegularLock(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "regular.lock")
	calls := 0
	for index := 0; index < 2; index++ {
		if err := withFileLock(lockPath, time.Second, func() error {
			calls++
			return nil
		}); err != nil {
			t.Fatalf("withFileLock call %d: %v", index+1, err)
		}
	}
	info, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || calls != 2 {
		t.Fatalf("lock state = mode %v, calls %d; want regular file and 2 callbacks", info.Mode(), calls)
	}
}

func TestQueueResetsSymlinkCursorWithoutSkippingPrompt(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	event := sampleEvent("cursor-symlink-event", "prompt behind linked cursor")
	if err := queue.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	queueInfo, err := os.Stat(queue.path)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside.cursor")
	sentinel := []byte(fmt.Sprintf("%d\n", queueInfo.Size()))
	if err := os.WriteFile(target, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	requireStorageSymlink(t, target, queue.cursorPath)

	if count, err := queue.Count(); err != nil || count != 1 {
		t.Fatalf("Count with linked cursor = %d, %v; want 1, nil", count, err)
	}
	if _, err := os.Lstat(queue.cursorPath); !os.IsNotExist(err) {
		t.Fatalf("linked cursor was not reset: %v", err)
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, sentinel) {
		t.Fatal("cursor symlink target was modified")
	}
}

func TestQueueResetsOversizedCursorWithoutSkippingPrompt(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(sampleEvent("oversized-cursor-event", "prompt behind oversized cursor")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		queue.cursorPath,
		[]byte(strings.Repeat("9", maxQueueCursorBytes+1)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if count, err := queue.Count(); err != nil || count != 1 {
		t.Fatalf("Count with oversized cursor = %d, %v; want 1, nil", count, err)
	}
	if _, err := os.Lstat(queue.cursorPath); !os.IsNotExist(err) {
		t.Fatalf("oversized cursor was not reset: %v", err)
	}
}

func newCloneAnchorTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	gitDirectory := filepath.Join(root, ".git")
	if err := os.MkdirAll(gitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-24 * time.Hour)
	if err := os.Chtimes(gitDirectory, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(localStoreDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCloneAnchorRejectsFutureCacheAndReplacesItAtomically(t *testing.T) {
	root := newCloneAnchorTestRoot(t)
	cache := filepath.Join(localStoreDir(root), cloneAnchorFileName)
	future := time.Now().UTC().Add(24 * time.Hour)
	if err := os.WriteFile(cache, []byte(future.Format(time.RFC3339Nano)), 0o600); err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC()
	got := cloneAnchorTime(root)
	if got.IsZero() || got.After(before.Add(cloneAnchorClockSkew)) {
		t.Fatalf("cloneAnchorTime accepted a future anchor: %v", got)
	}
	persisted, err := readCloneAnchor(cache)
	if err != nil {
		t.Fatalf("read replaced clone anchor: %v", err)
	}
	if !persisted.Equal(got) {
		t.Fatalf("persisted clone anchor = %v, returned %v", persisted, got)
	}
}

func TestCloneAnchorReplacesSymlinkWithoutTouchingTarget(t *testing.T) {
	root := newCloneAnchorTestRoot(t)
	cache := filepath.Join(localStoreDir(root), cloneAnchorFileName)
	target := filepath.Join(t.TempDir(), "outside.since")
	sentinel := []byte("outside clone-anchor sentinel\n")
	if err := os.WriteFile(target, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	requireStorageSymlink(t, target, cache)

	got := cloneAnchorTime(root)
	if got.IsZero() {
		t.Fatal("cloneAnchorTime returned zero after rejecting linked cache")
	}
	info, err := os.Lstat(cache)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("clone anchor mode = %v, want regular file", info.Mode())
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, sentinel) {
		t.Fatal("clone-anchor symlink target was modified")
	}
}

func TestCloneAnchorRejectsSymlinkStorageDirectory(t *testing.T) {
	root := t.TempDir()
	gitDirectory := filepath.Join(root, ".git")
	if err := os.MkdirAll(gitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	devtoolsDirectory := filepath.Join(root, ".devtools")
	if err := os.MkdirAll(devtoolsDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	outsideAnchor := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	outsidePath := filepath.Join(outside, cloneAnchorFileName)
	sentinel := []byte(outsideAnchor.Format(time.RFC3339Nano))
	if err := os.WriteFile(outsidePath, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	requireStorageSymlink(t, outside, localStoreDir(root))

	got := cloneAnchorTime(root)
	if got.IsZero() || got.Equal(outsideAnchor) {
		t.Fatalf("cloneAnchorTime trusted an anchor through a linked storage directory: %v", got)
	}
	after, err := os.ReadFile(outsidePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, sentinel) {
		t.Fatal("linked clone-anchor storage was modified")
	}
}

func TestCloneAnchorRejectsOversizedCache(t *testing.T) {
	root := newCloneAnchorTestRoot(t)
	cache := filepath.Join(localStoreDir(root), cloneAnchorFileName)
	if err := os.WriteFile(cache, []byte(strings.Repeat("2", maxCloneAnchorBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}

	got := cloneAnchorTime(root)
	if got.IsZero() {
		t.Fatal("cloneAnchorTime returned zero after rejecting oversized cache")
	}
	persisted, err := readCloneAnchor(cache)
	if err != nil {
		t.Fatalf("read rewritten clone anchor: %v", err)
	}
	if !persisted.Equal(got) {
		t.Fatalf("persisted clone anchor = %v, returned %v", persisted, got)
	}
}
