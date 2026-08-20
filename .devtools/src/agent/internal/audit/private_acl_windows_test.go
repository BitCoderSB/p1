//go:build windows

package audit

import (
	"crypto/sha256"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

var privateACLConvertSecurityDescriptorToString = privateACLAdvapi32.NewProc(
	"ConvertSecurityDescriptorToStringSecurityDescriptorW",
)

func privateDACLStringForTest(t *testing.T, path string, directory bool) string {
	t.Helper()
	file, err := openPrivateSecurityHandle(path, directory, false)
	if err != nil {
		t.Fatalf("open ACL fixture: %v", err)
	}
	defer file.Close()
	var descriptor uintptr
	result, _, _ := privateACLGetSecurityInfo.Call(
		file.Fd(),
		privateACLSEFileObject,
		privateACLDACLSecurityInformation,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&descriptor)),
	)
	if result != 0 {
		t.Fatalf("GetSecurityInfo(DACL) = %v", syscall.Errno(result))
	}
	if descriptor == 0 {
		t.Fatal("GetSecurityInfo returned no descriptor")
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	var encoded *uint16
	result, _, callErr := privateACLConvertSecurityDescriptorToString.Call(
		descriptor,
		privateACLSecurityDescriptorRevision,
		privateACLDACLSecurityInformation,
		uintptr(unsafe.Pointer(&encoded)),
		0,
	)
	if result == 0 {
		t.Fatalf("ConvertSecurityDescriptorToString = %v", callErr)
	}
	if encoded == nil {
		t.Fatal("converted DACL string is missing")
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(encoded))))
	buffer := unsafe.Slice(encoded, 64*1024)
	length := 0
	for length < len(buffer) && buffer[length] != 0 {
		length++
	}
	if length == len(buffer) {
		t.Fatal("converted DACL string is not terminated")
	}
	return syscall.UTF16ToString(buffer[:length])
}

func assertPrivateWindowsDACL(t *testing.T, sddl, authorityRoot string) {
	t.Helper()
	if !strings.HasPrefix(sddl, "D:P") {
		t.Fatalf("DACL is not protected: %q", sddl)
	}
	authority, err := openPrivateSecurityHandle(authorityRoot, true, false)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := privateHandleOwnerSID(authority)
	_ = authority.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{owner, "SY", "BA"} {
		if !strings.Contains(sddl, ";;;"+required+")") {
			t.Fatalf("private DACL omitted %s: %q", required, sddl)
		}
	}
	if group, err := user.LookupGroup("CodexSandboxUsers"); err == nil {
		sandboxSID, sidErr := canonicalPrivateSID(group.Gid)
		if sidErr != nil {
			t.Fatal(sidErr)
		}
		if !strings.Contains(sddl, ";;;"+sandboxSID+")") {
			t.Fatalf("private DACL omitted Codex sandbox group: %q", sddl)
		}
	}
	for _, forbidden := range []string{
		";;;WD)",
		";;;AU)",
		";;;BU)",
		";;;BG)",
		";;;AN)",
		";;;S-1-1-0)",
		";;;S-1-5-11)",
		";;;S-1-5-32-545)",
		";;;S-1-5-32-546)",
	} {
		if strings.Contains(sddl, forbidden) {
			t.Fatalf("private DACL grants broad principal %q: %q", forbidden, sddl)
		}
	}
}

func TestPrivateWindowsACLIsCrossContextAndPromptBytesStayUntouched(t *testing.T) {
	root := t.TempDir()
	local := filepath.Join(root, ".devtools", localStoreDirName)
	if err := os.MkdirAll(local, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectPrivateDirectory(root, local); err != nil {
		t.Fatalf("protect private directory: %v", err)
	}
	assertPrivateWindowsDACL(t, privateDACLStringForTest(t, local, true), root)

	const synthetic = "synthetic ACL migration payload\n"
	path := filepath.Join(local, "synthetic.jsonl")
	if err := os.WriteFile(path, []byte(synthetic), 0o600); err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256([]byte(synthetic))

	ownerHandle, err := openPrivateSecurityHandle(root, true, false)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := privateHandleOwnerSID(ownerHandle)
	_ = ownerHandle.Close()
	if err != nil {
		t.Fatal(err)
	}
	legacyHandle, err := openPrivateSecurityHandle(path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := setPrivateHandleDACL(legacyHandle, "D:P(A;;FA;;;"+owner+")"); err != nil {
		_ = legacyHandle.Close()
		t.Fatalf("install legacy single-account DACL: %v", err)
	}
	if err := legacyHandle.Close(); err != nil {
		t.Fatal(err)
	}

	if err := repairPrivateStoreACLs(root); err != nil {
		t.Fatalf("repairPrivateStoreACLs() = %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	after := sha256.Sum256(contents)
	if before != after {
		t.Fatal("ACL migration changed synthetic private bytes")
	}
	assertPrivateWindowsDACL(t, privateDACLStringForTest(t, path, false), root)
}

func TestPrivateWindowsACLCopiesSpecificAuthorityCapabilitySID(t *testing.T) {
	root := t.TempDir()
	handle, err := openPrivateSecurityHandle(root, true, true)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := privateHandleOwnerSID(handle)
	if err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	// A valid, intentionally unmapped account SID models the workspace-specific
	// restricting SID stamped by the Codex sandbox manager.
	const capabilitySID = "S-1-5-21-4242424242-3131313131-2121212121-1111111111"
	authoritySDDL := "D:P" +
		"(A;OICI;FA;;;" + owner + ")" +
		"(A;OICI;0x1301bf;;;" + capabilitySID + ")" +
		"(A;OICI;0x1301bf;;;BU)" +
		"(A;OICI;FA;;;SY)" +
		"(A;OICI;FA;;;BA)"
	if err := setPrivateHandleDACL(handle, authoritySDDL); err != nil {
		_ = handle.Close()
		t.Fatalf("install synthetic authority DACL: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}

	privateDirectory := filepath.Join(root, "private")
	if err := os.Mkdir(privateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectPrivateDirectory(root, privateDirectory); err != nil {
		t.Fatalf("protect private directory from synthetic authority: %v", err)
	}
	sddl := privateDACLStringForTest(t, privateDirectory, true)
	if !strings.Contains(sddl, ";;;"+capabilitySID+")") {
		t.Fatalf("private DACL omitted authority capability SID: %q", sddl)
	}
	if strings.Contains(sddl, ";;;BU)") ||
		strings.Contains(sddl, ";;;S-1-5-32-545)") {
		t.Fatalf("private DACL copied broad Users ACE: %q", sddl)
	}
}
