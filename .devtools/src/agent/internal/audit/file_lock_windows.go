//go:build windows

package audit

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	lockFileFailImmediately = 0x1
	lockFileExclusive       = 0x2
	errorLockViolation      = syscall.Errno(33)
)

var (
	lockFileExW   = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
	unlockFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("UnlockFileEx")
)

func tryFileLock(file *os.File) (func() error, bool, error) {
	overlapped := new(syscall.Overlapped)
	result, _, callErr := lockFileExW.Call(
		file.Fd(),
		lockFileFailImmediately|lockFileExclusive,
		0,
		1,
		0,
		uintptr(unsafe.Pointer(overlapped)),
	)
	if result == 0 {
		if errors.Is(callErr, errorLockViolation) {
			return nil, false, nil
		}
		if callErr == syscall.Errno(0) {
			callErr = syscall.EINVAL
		}
		return nil, false, os.NewSyscallError("LockFileEx", callErr)
	}
	return func() error {
		unlocked, _, unlockErr := unlockFileExW.Call(
			file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(overlapped)),
		)
		if unlocked == 0 {
			if unlockErr == syscall.Errno(0) {
				unlockErr = syscall.EINVAL
			}
			return os.NewSyscallError("UnlockFileEx", unlockErr)
		}
		return nil
	}, true, nil
}
