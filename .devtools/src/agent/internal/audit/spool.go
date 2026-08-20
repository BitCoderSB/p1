package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/acme/prompt-audit-template/internal/model"
)

// The authoritative backup is a single per-worker file guarded by a lock, which
// is the right shape for a store that has to stay ordered and repairable. It
// does mean a capture can fail for reasons that have nothing to do with the
// prompt: another process holding the lock longer than the timeout, an
// antivirus or sync client briefly holding the handle open, a permission
// system that momentarily refuses the protected reopen.
//
// Those are transient, and the previous behaviour on any of them was the worst
// possible one: capture exited non-zero, which makes Claude Code and Codex
// refuse the worker's prompt and print an error at them.
//
// The spool removes that failure mode. Each spooled event is written to its own
// uniquely named file, so it needs no lock and cannot collide with anything.
// Reconciliation, background recovery and session start absorb the spool back
// into the authoritative backup. A prompt therefore survives even when the main
// store is momentarily unusable, and the worker is never interrupted.

const spoolDirName = "pending"

func spoolDir(repoRoot string) string {
	return filepath.Join(localStoreDir(repoRoot), spoolDirName)
}

// spoolLocalEvent persists one event outside the locked authoritative file.
func spoolLocalEvent(repoRoot string, event model.Event) error {
	if err := validateStoredEvent(event); err != nil {
		return err
	}
	directory := spoolDir(repoRoot)
	if err := validateDirectoryTree(repoRoot, directory); err != nil {
		return err
	}
	if err := ensureDirectoryDurableUnder(repoRoot, directory, 0o700); err != nil {
		return err
	}
	if err := protectPrivateDirectory(repoRoot, directory); err != nil {
		return err
	}
	line, err := json.Marshal(event)
	if err != nil {
		return errors.New("encode spooled event")
	}
	line = append(line, '\n')
	identifier, err := newUUID()
	if err != nil {
		return err
	}
	path := filepath.Join(directory, identifier+registryFileExt)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(line); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return syncDirectory(directory)
}

// absorbSpooledEvents moves every spooled event into the authoritative backup
// and removes the spool file only after the append is durable. A crash between
// the two leaves the event spooled, so the next pass re-appends it; the
// duplicate event_id is collapsed by the existing dedupe on read.
func absorbSpooledEvents(repoRoot string) (int, error) {
	directory := spoolDir(repoRoot)
	if err := validateDirectoryTree(repoRoot, directory); err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), registryFileExt) {
			continue
		}
		names = append(names, entry.Name())
	}
	// A deterministic order keeps repeated absorption of the same spool
	// producing the same authoritative ordering.
	sort.Strings(names)

	absorbed := 0
	var problems []error
	for _, name := range names {
		path := filepath.Join(directory, name)
		event, readErr := readSpooledEvent(repoRoot, path)
		if readErr != nil {
			// An unreadable or invalid spool file can never become an event.
			// Drop it rather than blocking every later prompt behind it.
			_ = os.Remove(path)
			problems = append(problems, readErr)
			continue
		}
		if err := writeLocalEvent(repoRoot, event); err != nil {
			problems = append(problems, err)
			continue
		}
		if err := os.Remove(path); err != nil {
			problems = append(problems, err)
			continue
		}
		absorbed++
	}
	if absorbed > 0 {
		_ = syncDirectory(directory)
	}
	return absorbed, errors.Join(problems...)
}

func trimTrailingNewline(contents []byte) []byte {
	for len(contents) > 0 &&
		(contents[len(contents)-1] == '\n' || contents[len(contents)-1] == '\r') {
		contents = contents[:len(contents)-1]
	}
	return contents
}

func readSpooledEvent(repoRoot, path string) (model.Event, error) {
	file, err := openProtectedRegularFile(repoRoot, path, os.O_RDONLY, 0o600)
	if err != nil {
		return model.Event{}, err
	}
	defer file.Close()
	contents, err := ioReadAllLimit(file, int64(maxQueuedPromptBytes)+64*1024)
	if err != nil {
		return model.Event{}, err
	}
	event, err := decodeStoredEventLine(trimTrailingNewline(contents))
	if err != nil {
		return model.Event{}, err
	}
	if err := validateStoredEvent(event); err != nil {
		return model.Event{}, err
	}
	return event, nil
}
