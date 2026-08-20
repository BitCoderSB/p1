//go:build windows

package audit

import "syscall"

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procSetPriorityClass     = kernel32.NewProc("SetPriorityClass")
	procGetCurrentProcessAPI = kernel32.NewProc("GetCurrentProcess")
)

// enterBackgroundPriority makes this process yield to everything the worker is
// doing. A failure is ignored on purpose: running at normal priority is worse
// than ideal but still correct, and recovery must never abort over it.
//
// The class is set here as well as in the creation flags so that the intent
// survives however the process was started.
//
// PROCESS_MODE_BACKGROUND_BEGIN is deliberately NOT used, even though it is the
// only flag that would also lower I/O priority. Measured on this machine, it
// reports success and then puts the priority class back to NORMAL (0x20),
// undoing the idle class — the effect that made an earlier build run this pass
// at normal priority. An unverifiable I/O benefit is not worth losing the CPU
// guarantee that can be observed.
func enterBackgroundPriority() {
	handle, _, _ := procGetCurrentProcessAPI.Call()
	if handle == 0 {
		return
	}
	_, _, _ = procSetPriorityClass.Call(handle, idlePriorityClass)
}
