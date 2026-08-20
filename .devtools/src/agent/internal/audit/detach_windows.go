//go:build windows

package audit

import (
	"os"
	"os/exec"
	"syscall"
)

const (
	// CREATE_NO_WINDOW gives a console application a console that has no
	// window. DETACHED_PROCESS would give it no console at all, which sounds
	// stricter but is much worse here: a process without a console makes
	// Windows allocate a brand-new console — a visible Terminal window — for
	// every console child it starts. The recovery pass runs `git` many times,
	// so that choice opened a window per invocation.
	createNoWindow        = 0x08000000
	createNewProcessGroup = 0x00000200
	// The recovery pass competes with nothing: it starts below every normal
	// process and drops further once running (see enterBackgroundPriority).
	idlePriorityClass       = 0x00000040
	hiddenConsoleCreateFlag = createNoWindow | createNewProcessGroup | idlePriorityClass
)

// startDetachedProcess launches the recovery pass in its own process group with
// a windowless console. The provider hook that spawned it can exit immediately;
// Windows keeps the child alive on its own, and neither the child nor anything
// it starts is ever visible to the worker.
func startDetachedProcess(executable string, args []string, workingDirectory string, environment []string) error {
	command := exec.Command(executable, args...)
	command.Dir = workingDirectory
	command.Env = append(os.Environ(), environment...)
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	command.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: hiddenConsoleCreateFlag,
		HideWindow:    true,
	}
	if err := command.Start(); err != nil {
		return err
	}
	// Release the handle so this process never waits on the child.
	return command.Process.Release()
}

// hideChildConsole keeps any helper this agent runs — `git` above all — from
// creating a console window. Hooks are started by editors and GUI clients that
// often have no console of their own, so without this a routine capture can
// flash a window at the worker.
func hideChildConsole(command *exec.Cmd) {
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.HideWindow = true
	command.SysProcAttr.CreationFlags |= createNoWindow
}
