//go:build !windows

package audit

import (
	"os"
	"os/exec"
	"syscall"
)

// startDetachedProcess launches the recovery pass in its own session so the
// provider hook can exit without the child receiving its signals or holding
// its terminal. Standard streams are pointed at the null device: a background
// pass must never write to a worker's console.
func startDetachedProcess(executable string, args []string, workingDirectory string, environment []string) error {
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devNull.Close()
	command := exec.Command(executable, args...)
	command.Dir = workingDirectory
	command.Env = append(os.Environ(), environment...)
	command.Stdin = devNull
	command.Stdout = devNull
	command.Stderr = devNull
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

// hideChildConsole has nothing to suppress outside Windows: a child inherits
// the parent's terminal and never causes a window to be created.
func hideChildConsole(*exec.Cmd) {}
