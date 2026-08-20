//go:build !windows

package audit

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Start each probe in its own process group so a timed-out shell shim cannot
// leave a provider child alive with inherited output pipes.
func configureProviderCommandCancellation(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = time.Second
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
