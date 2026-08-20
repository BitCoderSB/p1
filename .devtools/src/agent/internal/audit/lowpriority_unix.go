//go:build !windows

package audit

import "syscall"

// enterBackgroundPriority makes this process yield to everything the worker is
// doing. nice(19) is the lowest scheduling priority a normal user may request;
// lowering it can never fail in a way that matters, so the result is ignored.
func enterBackgroundPriority() {
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19)
}
