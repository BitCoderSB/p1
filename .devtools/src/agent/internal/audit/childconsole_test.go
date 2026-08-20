package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A child process that Windows has to give a console to opens a real Terminal
// window in front of the worker. The recovery pass runs `git` many times, so a
// single missed call here is not a cosmetic flaw: it floods the desktop with
// windows every time the project is opened. Every place that starts a helper
// process must therefore suppress the console explicitly.
func TestEveryChildProcessSuppressesItsConsole(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		source := string(contents)
		if !strings.Contains(source, "exec.Command") {
			continue
		}
		checked++
		if !strings.Contains(source, "hideChildConsole") &&
			!strings.Contains(source, "configureProviderCommandCancellation") {
			t.Errorf(
				"%s starts a child process without suppressing its console; "+
					"call hideChildConsole on the command",
				name,
			)
		}
	}
	if checked == 0 {
		t.Fatal("no file starting a child process was found; the guard is not testing anything")
	}
}

func TestHideChildConsoleIsSafeToApplyTwice(t *testing.T) {
	command := exec.Command("git", "--version")
	hideChildConsole(command)
	hideChildConsole(command)
	if err := command.Run(); err != nil {
		t.Skipf("git is unavailable in this environment: %v", err)
	}
}
