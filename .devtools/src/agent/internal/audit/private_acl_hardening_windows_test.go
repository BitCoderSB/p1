//go:build windows

package audit

import (
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// On Windows a group that does not exist surfaces from user.LookupGroup as
// syscall.Errno(1332), not as user.UnknownGroupError. The optional Codex
// sandbox group therefore has to be treated as absent on ANY lookup failure.
// When it was treated as fatal, a laptop that had never been provisioned for a
// managed Codex sandbox — which is every ordinary employee laptop — could not
// protect the private store, so activation exited non-zero and, far worse,
// every capture exited 2 and the provider refused the worker's prompt.
func TestMissingCodexSandboxGroupDoesNotBreakCapture(t *testing.T) {
	missing := "CodexSandboxUsersThatDoesNotExist7f3c2d91"
	if _, err := user.LookupGroup(missing); err == nil {
		t.Skipf("fixture group %q unexpectedly exists on this machine", missing)
	} else if _, unknown := err.(user.UnknownGroupError); unknown {
		t.Log("this Windows build reports UnknownGroupError; the regression is still worth guarding")
	}

	previous := codexSandboxGroupName
	codexSandboxGroupName = missing
	t.Cleanup(func() { codexSandboxGroupName = previous })

	root := t.TempDir()
	authority, err := openPrivateSecurityHandle(root, true, false)
	if err != nil {
		t.Fatalf("open authority handle: %v", err)
	}
	owner, sids, err := privateHandleAuthoritySIDs(authority)
	_ = authority.Close()
	if err != nil {
		t.Fatalf("read authority SIDs: %v", err)
	}

	sddl, err := privateSecurityDescriptor(owner, sids, true)
	if err != nil {
		t.Fatalf("a missing Codex sandbox group must not fail the private DACL: %v", err)
	}
	if !strings.HasPrefix(sddl, "D:P") {
		t.Fatalf("the fallback DACL must stay protected: %q", sddl)
	}
	if !strings.Contains(sddl, ";;;"+owner+")") {
		t.Fatalf("the fallback DACL must still grant the owner: %q", sddl)
	}

	// The whole storage path has to work, not just the descriptor: this is the
	// exact sequence a capture performs before it can report success.
	if err := preparePrivateLocalStore(root); err != nil {
		t.Fatalf("prepare private store without the sandbox group: %v", err)
	}
	if err := probeLocalStoreDurability(root); err != nil {
		t.Fatalf("durability probe without the sandbox group: %v", err)
	}
	if err := protectPrivateDirectory(root, filepath.Join(root, ".devtools", localStoreDirName)); err != nil {
		t.Fatalf("protect private directory without the sandbox group: %v", err)
	}
}
