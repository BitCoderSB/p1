package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const healthLogFileName = "health.log"

// The agent routes most degradations to the health log rather than failing:
// a session must not end and a commit must not break because a scanner had a
// bad pass. That is only the right trade-off if somebody eventually reads the
// log. Nothing did — every mention of the file outside tests was the writer
// itself — so those warnings were being filed somewhere nobody would ever open.
// summarizeLocalHealth gives `status` something to show.
const (
	maxHealthSummaryBytes   = 256 * 1024
	maxHealthSummaryEntries = 5
)

type healthSummary struct {
	Total  int
	Recent []string
}

// summarizeLocalHealth reads the tail of the health log. The file holds only
// generic operational messages by contract, so surfacing it cannot leak a
// prompt. An unreadable or absent log is simply an empty summary: a diagnostic
// must never fail because its own diagnostics are missing.
func summarizeLocalHealth(repoRoot string) healthSummary {
	path := filepath.Join(localStoreDir(repoRoot), healthLogFileName)
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return healthSummary{}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return healthSummary{}
	}
	offset := int64(0)
	if info.Size() > maxHealthSummaryBytes {
		offset = info.Size() - maxHealthSummaryBytes
	}
	if _, err := file.Seek(offset, 0); err != nil {
		return healthSummary{}
	}
	contents := make([]byte, info.Size()-offset)
	read, err := file.Read(contents)
	if err != nil && read == 0 {
		return healthSummary{}
	}
	lines := make([]string, 0)
	for _, line := range strings.Split(string(contents[:read]), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	// A truncated first line is an artefact of reading only the tail.
	if offset > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	summary := healthSummary{Total: len(lines)}
	if len(lines) > maxHealthSummaryEntries {
		summary.Recent = lines[len(lines)-maxHealthSummaryEntries:]
	} else {
		summary.Recent = lines
	}
	return summary
}

// recordLocalHealth stores operational state only. Callers must pass a generic
// message: prompt text, hook payloads and credentials never belong here.
func recordLocalHealth(repoRoot, message string) {
	message = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(message))
	if message == "" {
		return
	}
	if len(message) > 512 {
		message = message[:512]
	}
	dir := localStoreDir(repoRoot)
	if err := validateDirectoryTree(repoRoot, dir); err != nil {
		return
	}
	if err := ensureDirectoryDurableUnder(repoRoot, dir, 0o700); err != nil {
		return
	}
	if err := protectPrivateDirectory(repoRoot, dir); err != nil {
		return
	}
	lock := filepath.Join(dir, ".health.lock")
	_ = withFileLock(lock, 500*time.Millisecond, func() error {
		path := filepath.Join(dir, healthLogFileName)
		_, err := regularFileInfo(path)
		newFile := errors.Is(err, os.ErrNotExist)
		if err != nil && !newFile {
			return err
		}
		if newFile {
			created, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if createErr != nil {
				return createErr
			}
			if closeErr := created.Close(); closeErr != nil {
				return closeErr
			}
			if err := syncDirectory(dir); err != nil {
				return err
			}
		}
		file, err := openProtectedRegularFile(repoRoot, path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, writeErr := fmt.Fprintf(file, "%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), message)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		return nil
	})
}
