//go:build linux || darwin

package audit

import (
	"errors"
	"os"
	"syscall"
)

func tryFileLock(file *os.File) (func() error, bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return func() error { return syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }, true, nil
}
