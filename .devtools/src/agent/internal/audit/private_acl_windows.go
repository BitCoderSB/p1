//go:build windows

package audit

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

const (
	privateACLSEFileObject               = 1
	privateACLOwnerSecurityInformation   = 0x00000001
	privateACLDACLSecurityInformation    = 0x00000004
	privateACLProtectedDACLInformation   = 0x80000000
	privateACLReadControl                = 0x00020000
	privateACLWriteDACL                  = 0x00040000
	privateACLFileReadAttributes         = 0x00000080
	privateACLShareRead                  = 0x00000001
	privateACLShareWrite                 = 0x00000002
	privateACLShareDelete                = 0x00000004
	privateACLOpenExisting               = 3
	privateACLFlagOpenReparsePoint       = 0x00200000
	privateACLFlagBackupSemantics        = 0x02000000
	privateACLFileAttributeReparsePoint  = 0x00000400
	privateACLSecurityDescriptorRevision = 1
	privateACLAccessAllowedACEType       = 0
)

var (
	privateACLAdvapi32 = syscall.NewLazyDLL("advapi32.dll")

	privateACLGetSecurityInfo = privateACLAdvapi32.NewProc(
		"GetSecurityInfo",
	)
	privateACLSetSecurityInfo = privateACLAdvapi32.NewProc(
		"SetSecurityInfo",
	)
	privateACLConvertStringSecurityDescriptor = privateACLAdvapi32.NewProc(
		"ConvertStringSecurityDescriptorToSecurityDescriptorW",
	)
	privateACLGetSecurityDescriptorDACL = privateACLAdvapi32.NewProc(
		"GetSecurityDescriptorDacl",
	)
	privateACLCheckTokenMembership = privateACLAdvapi32.NewProc(
		"CheckTokenMembership",
	)
	privateACLGetAce = privateACLAdvapi32.NewProc(
		"GetAce",
	)
	privateACLIsValidSid = privateACLAdvapi32.NewProc(
		"IsValidSid",
	)
	privateACLGetLengthSid = privateACLAdvapi32.NewProc(
		"GetLengthSid",
	)
)

// codexSandboxGroupName is a variable so the "group does not exist on this
// machine" path — the state of every laptop that has not been provisioned for
// a managed Codex sandbox — can be exercised by a test. On Windows a missing
// group surfaces as syscall.Errno(1332) rather than user.UnknownGroupError, so
// this used to be an unhandled failure that refused the worker's prompt.
var codexSandboxGroupName = "CodexSandboxUsers"

type privateACLHeader struct {
	Revision byte
	_        byte
	Size     uint16
	Count    uint16
	_        uint16
}

type privateACEHeader struct {
	Type  byte
	Flags byte
	Size  uint16
}

// protectPrivateFile replaces inherited or context-specific Windows DACLs with
// a protected allow-list. The owner of the authority directory remains able to
// use the file from Claude/Copilot, while Codex managed sandboxes are covered
// by their local group instead of a short-lived per-process account.
func protectPrivateFile(authorityRoot, path string) error {
	return applyPrivatePathACL(authorityRoot, path, false)
}

func protectPrivateDirectory(authorityRoot, path string) error {
	return applyPrivatePathACL(authorityRoot, path, true)
}

func applyPrivatePathACL(authorityRoot, path string, directory bool) error {
	authority, err := openPrivateSecurityHandle(authorityRoot, true, false)
	if err != nil {
		return fmt.Errorf("open private ACL authority: %w", err)
	}
	ownerSID, authoritySIDs, err := privateHandleAuthoritySIDs(authority)
	closeErr := authority.Close()
	if err != nil {
		return fmt.Errorf("read private ACL authority: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close private ACL authority: %w", closeErr)
	}

	sddl, err := privateSecurityDescriptor(ownerSID, authoritySIDs, directory)
	if err != nil {
		return err
	}
	target, err := openPrivateSecurityHandle(path, directory, true)
	if err != nil {
		return fmt.Errorf("open private ACL target: %w", err)
	}
	defer target.Close()
	if err := setPrivateHandleDACL(target, sddl); err != nil {
		return fmt.Errorf("set private ACL: %w", err)
	}
	return nil
}

func openPrivateSecurityHandle(path string, directory, writeDACL bool) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	linkLike, err := pathIsLinkLike(path, before)
	if err != nil {
		return nil, err
	}
	if linkLike || before.IsDir() != directory ||
		(!directory && !before.Mode().IsRegular()) {
		return nil, errors.New("private ACL target has an unexpected type")
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	access := uint32(privateACLReadControl | privateACLFileReadAttributes)
	if writeDACL {
		access |= privateACLWriteDACL
	}
	handle, err := syscall.CreateFile(
		name,
		access,
		privateACLShareRead|privateACLShareWrite|privateACLShareDelete,
		nil,
		privateACLOpenExisting,
		privateACLFlagOpenReparsePoint|privateACLFlagBackupSemantics,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, errors.New("wrap private ACL handle")
	}
	after, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	attributes, ok := after.Sys().(*syscall.Win32FileAttributeData)
	if !os.SameFile(before, after) || after.IsDir() != directory ||
		!ok || attributes.FileAttributes&privateACLFileAttributeReparsePoint != 0 {
		_ = file.Close()
		return nil, errors.New("private ACL target changed during validation")
	}
	return file, nil
}

func privateHandleOwnerSID(file *os.File) (string, error) {
	owner, _, err := privateHandleAuthoritySIDs(file)
	return owner, err
}

// privateHandleAuthoritySIDs returns the owner and every specific allow ACE
// already required to write the authority root. Codex on Windows uses a
// restricted token: both its normal group SID and workspace capability SID
// must pass AccessCheck. Copying only CodexSandboxUsers would therefore make a
// protected child inaccessible from the managed sandbox.
func privateHandleAuthoritySIDs(file *os.File) (string, []string, error) {
	var owner *syscall.SID
	var dacl *privateACLHeader
	var descriptor uintptr
	result, _, _ := privateACLGetSecurityInfo.Call(
		file.Fd(),
		privateACLSEFileObject,
		privateACLOwnerSecurityInformation|privateACLDACLSecurityInformation,
		uintptr(unsafe.Pointer(&owner)),
		0,
		uintptr(unsafe.Pointer(&dacl)),
		0,
		uintptr(unsafe.Pointer(&descriptor)),
	)
	if result != 0 {
		return "", nil, syscall.Errno(result)
	}
	if descriptor == 0 {
		return "", nil, errors.New("authority security descriptor is missing")
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	if owner == nil {
		return "", nil, errors.New("private ACL authority has no owner")
	}
	value, err := owner.String()
	if err != nil {
		return "", nil, err
	}
	ownerSID, err := canonicalPrivateSID(value)
	if err != nil {
		return "", nil, err
	}
	if dacl == nil {
		return "", nil, errors.New("private ACL authority has a missing or null DACL")
	}
	if dacl.Size < uint16(unsafe.Sizeof(privateACLHeader{})) {
		return "", nil, errors.New("private ACL authority has a malformed DACL")
	}
	principals := make(map[string]struct{})
	for index := uint16(0); index < dacl.Count; index++ {
		var ace *privateACEHeader
		ok, _, callErr := privateACLGetAce.Call(
			uintptr(unsafe.Pointer(dacl)),
			uintptr(index),
			uintptr(unsafe.Pointer(&ace)),
		)
		if ok == 0 {
			return "", nil, privateACLCallError(callErr)
		}
		if ace == nil {
			return "", nil, errors.New("private ACL authority returned a missing ACE")
		}
		if ace.Type != privateACLAccessAllowedACEType {
			continue
		}
		const sidOffset = uintptr(8) // ACE_HEADER (4) + access mask (4)
		if uintptr(ace.Size) <= sidOffset {
			return "", nil, errors.New("private ACL authority contains a malformed allow ACE")
		}
		sid := (*syscall.SID)(unsafe.Add(unsafe.Pointer(ace), sidOffset))
		valid, _, _ := privateACLIsValidSid.Call(uintptr(unsafe.Pointer(sid)))
		if valid == 0 {
			return "", nil, errors.New("private ACL authority contains an invalid SID")
		}
		length, _, _ := privateACLGetLengthSid.Call(uintptr(unsafe.Pointer(sid)))
		if length == 0 || sidOffset+length > uintptr(ace.Size) {
			return "", nil, errors.New("private ACL authority contains an out-of-bounds SID")
		}
		raw, err := sid.String()
		if err != nil {
			return "", nil, err
		}
		principal, err := canonicalPrivateSID(raw)
		if err != nil {
			return "", nil, err
		}
		if privateAuthorityPrincipalAllowed(principal, ownerSID) {
			principals[principal] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(principals))
	for principal := range principals {
		ordered = append(ordered, principal)
	}
	sort.Strings(ordered)
	return ownerSID, ordered, nil
}

func privateAuthorityPrincipalAllowed(principal, ownerSID string) bool {
	if principal == ownerSID ||
		principal == "S-1-5-18" || // SYSTEM
		principal == "S-1-5-32-544" { // BUILTIN\Administrators
		return true
	}
	// Account/domain SIDs and application capability SIDs are specific
	// principals. Preserve them because Windows restricted tokens may require
	// both a normal account/group ACE and a capability/restricting ACE.
	return strings.HasPrefix(principal, "S-1-5-21-") ||
		strings.HasPrefix(principal, "S-1-15-")
}

func privateSecurityDescriptor(ownerSID string, authoritySIDs []string, directory bool) (string, error) {
	principals := map[string]struct{}{ownerSID: {}}
	for _, principal := range authoritySIDs {
		canonical, err := canonicalPrivateSID(principal)
		if err != nil {
			return "", fmt.Errorf("validate private ACL authority SID: %w", err)
		}
		if privateAuthorityPrincipalAllowed(canonical, ownerSID) {
			principals[canonical] = struct{}{}
		}
	}
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("resolve current Windows account: %w", err)
	}
	currentSID, err := canonicalPrivateSID(current.Uid)
	if err != nil {
		return "", fmt.Errorf("resolve current Windows SID: %w", err)
	}

	// The Codex sandbox group is an optional convenience: including it lets a
	// managed Codex sandbox reuse the same protected store. Its absence, and
	// equally a lookup that fails for an unrelated reason — an offline
	// domain-joined laptop, a slow directory service, a roaming profile — must
	// never be able to reject a worker's prompt. Fall back to an owner-only
	// DACL, which is stricter, not weaker.
	sandboxSID := ""
	if group, lookupErr := user.LookupGroup(codexSandboxGroupName); lookupErr == nil {
		if canonical, sidErr := canonicalPrivateSID(group.Gid); sidErr == nil {
			sandboxSID = canonical
			principals[sandboxSID] = struct{}{}
		}
	}
	if currentSID != ownerSID &&
		(sandboxSID == "" || !privateTokenContainsSID(sandboxSID)) {
		// A non-owner tool account outside the managed Codex group must retain
		// access if it was explicitly authorized to write in this directory.
		principals[currentSID] = struct{}{}
	}

	ordered := make([]string, 0, len(principals))
	for principal := range principals {
		ordered = append(ordered, principal)
	}
	sort.Strings(ordered)
	flags := ""
	if directory {
		flags = "OICI"
	}
	var builder strings.Builder
	builder.WriteString("D:P")
	for _, principal := range ordered {
		if principal == ownerSID {
			fmt.Fprintf(&builder, "(A;%s;FA;;;%s)", flags, principal)
			continue
		}
		// Modify plus WRITE_DAC lets either authorized execution context repair
		// a legacy DACL without granting WRITE_OWNER.
		fmt.Fprintf(&builder, "(A;%s;0x1701bf;;;%s)", flags, principal)
	}
	fmt.Fprintf(&builder, "(A;%s;FA;;;SY)(A;%s;FA;;;BA)", flags, flags)
	return builder.String(), nil
}

func canonicalPrivateSID(value string) (string, error) {
	if value == "" {
		return "", errors.New("Windows SID is empty")
	}
	sid, err := syscall.StringToSid(value)
	if err != nil {
		return "", err
	}
	canonical, err := sid.String()
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(canonical, "S-") {
		return "", errors.New("Windows SID is not canonical")
	}
	return canonical, nil
}

func privateTokenContainsSID(value string) bool {
	sid, err := syscall.StringToSid(value)
	if err != nil {
		return false
	}
	var member int32
	result, _, _ := privateACLCheckTokenMembership.Call(
		0,
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&member)),
	)
	runtime.KeepAlive(sid)
	return result != 0 && member != 0
}

func setPrivateHandleDACL(file *os.File, sddl string) error {
	encoded, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return err
	}
	var descriptor uintptr
	result, _, callErr := privateACLConvertStringSecurityDescriptor.Call(
		uintptr(unsafe.Pointer(encoded)),
		privateACLSecurityDescriptorRevision,
		uintptr(unsafe.Pointer(&descriptor)),
		0,
	)
	runtime.KeepAlive(encoded)
	if result == 0 {
		return privateACLCallError(callErr)
	}
	if descriptor == 0 {
		return errors.New("converted private security descriptor is missing")
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))

	var present int32
	var dacl uintptr
	var defaulted int32
	result, _, callErr = privateACLGetSecurityDescriptorDACL.Call(
		descriptor,
		uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&defaulted)),
	)
	if result == 0 {
		return privateACLCallError(callErr)
	}
	if present == 0 || dacl == 0 {
		return errors.New("refuse missing or null private DACL")
	}
	result, _, _ = privateACLSetSecurityInfo.Call(
		file.Fd(),
		privateACLSEFileObject,
		privateACLDACLSecurityInformation|privateACLProtectedDACLInformation,
		0,
		0,
		dacl,
		0,
	)
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}

func privateACLCallError(err error) error {
	if err == nil {
		return errors.New("Windows private ACL operation failed")
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return errors.New("Windows private ACL operation failed")
	}
	return err
}

// repairPrivateStoreACLs upgrades only file-system ACL metadata. WalkDir and
// Lstat inspect names and object types; no prompt-bearing file is opened for
// data and no bytes are read, hashed, copied, staged, or published.
func repairPrivateStoreACLs(repoRoot string) error {
	directory := localStoreDir(repoRoot)
	if err := validateDirectoryTree(repoRoot, directory); err != nil {
		return err
	}
	return filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == directory {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		linkLike, err := pathIsLinkLike(path, info)
		if err != nil {
			return err
		}
		if linkLike {
			return errors.New("linked private storage entry refused")
		}
		switch {
		case info.IsDir():
			return protectPrivateDirectory(repoRoot, path)
		case info.Mode().IsRegular():
			return protectPrivateFile(repoRoot, path)
		default:
			return errors.New("private storage contains a non-regular entry")
		}
	})
}
