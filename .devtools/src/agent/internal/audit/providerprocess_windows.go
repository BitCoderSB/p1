//go:build windows

package audit

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// configureProviderCommandCancellation makes a version-probe deadline apply to
// the complete process tree. Windows command shims normally start Node beneath
// cmd.exe; killing only the shell can leave the child holding stdout/stderr and
// make Cmd.Wait hang indefinitely.
func configureProviderCommandCancellation(command *exec.Cmd) {
	// A version probe must not flash a console window either; the diagnostic
	// can be invoked from an editor that has no console of its own.
	hideChildConsole(command)
	command.WaitDelay = time.Second
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		systemRoot := strings.TrimSpace(os.Getenv("SystemRoot"))
		if systemRoot != "" {
			taskkillPath := filepath.Join(systemRoot, "System32", "taskkill.exe")
			killContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			killer := exec.CommandContext(
				killContext,
				taskkillPath,
				"/PID",
				strconv.Itoa(command.Process.Pid),
				"/T",
				"/F",
			)
			hideChildConsole(killer)
			killer.Stdout = io.Discard
			killer.Stderr = io.Discard
			if err := killer.Run(); err == nil {
				return nil
			}
		}
		err := command.Process.Kill()
		if errors.Is(err, os.ErrProcessDone) {
			return os.ErrProcessDone
		}
		return err
	}
}
