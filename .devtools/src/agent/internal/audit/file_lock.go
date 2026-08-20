package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func withFileLock(path string, timeout time.Duration, fn func() error) error {
	if err := ensureDirectoryDurable(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create lock directory: %w", err)
	}
	file, err := openOrCreateLockFile(path)
	if err != nil {
		return fmt.Errorf("open lock: %w", err)
	}
	defer file.Close()
	deadline := time.Now().Add(timeout)
	for {
		unlock, acquired, lockErr := tryFileLock(file)
		if lockErr != nil {
			return fmt.Errorf("lock file: %w", lockErr)
		}
		if acquired {
			defer func() { _ = unlock() }()
			if err := verifyOpenedRegularFile(path, file); err != nil {
				return fmt.Errorf("verify acquired lock: %w", err)
			}
			return fn()
		}
		if time.Now().After(deadline) {
			return errors.New("local audit storage is busy")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func openOrCreateLockFile(path string) (*os.File, error) {
	for attempt := 0; attempt < 3; attempt++ {
		file, err := openExistingRegularFile(path, os.O_RDWR, 0o600)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		file, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := verifyOpenedRegularFile(path, file); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			_ = file.Close()
			return nil, err
		}
		return file, nil
	}
	return nil, errors.New("lock file changed repeatedly while it was being opened")
}

func verifyOpenedRegularFile(path string, file *os.File) error {
	observed, err := regularFileInfo(path)
	if err != nil {
		return err
	}
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(observed, opened) {
		return errors.New("lock file changed while it was being opened")
	}
	return nil
}
