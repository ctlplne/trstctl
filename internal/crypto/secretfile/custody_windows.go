// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package secretfile

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validateNonUnixParent(string, os.FileInfo) error { return nil }

func validateNonUnixFile(path string, _ os.FileInfo) error {
	private, err := privateWindowsPath(path)
	if err != nil {
		return fmt.Errorf("secretfile: inspect %s DACL: %w", path, err)
	}
	if !private {
		return fmt.Errorf("secretfile: %s has an unsafe Windows DACL", path)
	}
	return nil
}

func securePrivateDirectoryPermissions(path string) error { return setWindowsDACL(path, true, false) }
func securePrivateFilePermissions(path string) error      { return setWindowsDACL(path, false, false) }
func securePublicFilePermissions(path string) error       { return setWindowsDACL(path, false, true) }

func privateFilePermissions(path string, _ os.FileInfo) (bool, error) {
	return privateWindowsPath(path)
}

func publicFilePermissions(path string, _ os.FileInfo) (bool, error) {
	return publicWindowsPathTamperSafe(path)
}

func setWindowsDACL(path string, directory, publicRead bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("secretfile: read process SID: %w", err)
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	sddl := fmt.Sprintf("D:P(A;%s;FA;;;%s)(A;%s;FA;;;SY)(A;%s;FA;;;BA)",
		flags, user.User.Sid.String(), flags, flags)
	if publicRead {
		sddl += "(A;;GR;;;BU)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("secretfile: build protected DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("secretfile: build protected DACL body: %w", err)
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

func privateWindowsPath(path string) (bool, error) {
	sd, owner, dacl, err := windowsPathSecurity(path)
	if err != nil || sd == nil || dacl == nil {
		return false, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	allowed := windowsTrustedWriters(owner, user.User.Sid)
	aces, err := windowsAllowedACEs(dacl)
	if err != nil || len(aces) == 0 {
		return false, err
	}
	for _, ace := range aces {
		if ace.Mask == 0 {
			continue
		}
		sid := windowsACESID(ace)
		if sid == nil || !sid.IsValid() {
			return false, nil
		}
		trustee := strings.ToUpper(sid.String())
		if _, ok := allowed[trustee]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func windowsTrustedWriters(owner, user *windows.SID) map[string]struct{} {
	allowed := map[string]struct{}{
		"S-1-5-18":     {}, // Local System.
		"S-1-5-32-544": {}, // Built-in Administrators.
		"S-1-3-4":      {}, // Owner Rights.
	}
	if user != nil {
		allowed[strings.ToUpper(user.String())] = struct{}{}
	}
	if owner != nil {
		allowed[strings.ToUpper(owner.String())] = struct{}{}
	}
	return allowed
}

func publicWindowsPathTamperSafe(path string) (bool, error) {
	_, owner, dacl, err := windowsPathSecurity(path)
	if err != nil {
		return false, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	allowedWriters := windowsTrustedWriters(owner, user.User.Sid)
	aces, err := windowsAllowedACEs(dacl)
	if err != nil || len(aces) == 0 {
		return false, err
	}
	for _, ace := range aces {
		if ace.Mask == 0 {
			continue
		}
		sid := windowsACESID(ace)
		if sid == nil || !sid.IsValid() {
			return false, nil
		}
		trustee := strings.ToUpper(sid.String())
		if _, ok := allowedWriters[trustee]; ok {
			continue
		}
		if windowsMaskMayWrite(ace.Mask) {
			return false, nil
		}
	}
	return true, nil
}

func windowsPathSecurity(path string) (*windows.SECURITY_DESCRIPTOR, *windows.SID, *windows.ACL, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return sd, nil, nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return sd, nil, dacl, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return sd, nil, dacl, err
	}
	return sd, owner, dacl, nil
}

func windowsAllowedACEs(dacl *windows.ACL) ([]*windows.ACCESS_ALLOWED_ACE, error) {
	aces := make([]*windows.ACCESS_ALLOWED_ACE, 0, dacl.AceCount)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return nil, err
		}
		if ace == nil {
			return nil, fmt.Errorf("secretfile: Windows DACL contains a nil ACE")
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			aces = append(aces, ace)
		case windows.ACCESS_DENIED_ACE_TYPE:
			// A deny ACE grants no mutation authority and is safe to ignore.
		default:
			// Object/callback/conditional allow ACEs have a different SID
			// layout. Refuse them instead of interpreting the wrong bytes.
			return nil, fmt.Errorf("secretfile: Windows DACL contains unsupported ACE type %d", ace.Header.AceType)
		}
	}
	return aces, nil
}

func windowsACESID(ace *windows.ACCESS_ALLOWED_ACE) *windows.SID {
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart))
}

func windowsMaskMayWrite(mask windows.ACCESS_MASK) bool {
	const readOnly = uint32(windows.GENERIC_READ | windows.GENERIC_EXECUTE |
		windows.FILE_READ_DATA | windows.FILE_READ_EA | windows.FILE_READ_ATTRIBUTES |
		windows.FILE_EXECUTE | windows.READ_CONTROL | windows.SYNCHRONIZE)
	// Anything beyond the exact read/execute/control set is conservatively
	// treated as mutation authority. This includes generic/full write, append,
	// delete, DACL/owner changes, and any future mask this verifier does not know.
	return uint32(mask)&^readOnly != 0
}
