// SPDX-License-Identifier: MPL-2.0

//go:build windows

package secretfile

import (
	"fmt"
	"os"
	"strings"

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
	sd, owner, sddl, err := windowsPathSecurity(path)
	if err != nil || sd == nil {
		return false, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	allowed := map[string]struct{}{
		"SY": {}, "S-1-5-18": {}, "BA": {}, "S-1-5-32-544": {}, "OW": {},
		strings.ToUpper(user.User.Sid.String()): {},
	}
	if owner != nil {
		allowed[strings.ToUpper(owner.String())] = struct{}{}
	}
	aces := daclACEs(sddl)
	if len(aces) == 0 {
		return false, nil
	}
	for _, ace := range aces {
		fields := strings.Split(ace, ";")
		if len(fields) < 6 || !windowsAllowACE(fields[0]) || strings.TrimSpace(fields[2]) == "" {
			continue
		}
		trustee := strings.ToUpper(strings.TrimSpace(fields[len(fields)-1]))
		if _, ok := allowed[trustee]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func publicWindowsPathTamperSafe(path string) (bool, error) {
	_, owner, sddl, err := windowsPathSecurity(path)
	if err != nil {
		return false, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	allowedWriters := map[string]struct{}{
		"SY": {}, "S-1-5-18": {}, "BA": {}, "S-1-5-32-544": {}, "OW": {},
		strings.ToUpper(user.User.Sid.String()): {},
	}
	if owner != nil {
		allowedWriters[strings.ToUpper(owner.String())] = struct{}{}
	}
	aces := daclACEs(sddl)
	if len(aces) == 0 {
		return false, nil
	}
	for _, ace := range aces {
		fields := strings.Split(ace, ";")
		if len(fields) < 6 || !windowsAllowACE(fields[0]) || strings.TrimSpace(fields[2]) == "" {
			continue
		}
		trustee := strings.ToUpper(strings.TrimSpace(fields[len(fields)-1]))
		if _, ok := allowedWriters[trustee]; ok {
			continue
		}
		if windowsRightsMayWrite(fields[2]) {
			return false, nil
		}
	}
	return true, nil
}

func windowsPathSecurity(path string) (*windows.SECURITY_DESCRIPTOR, *windows.SID, string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return sd, nil, "", err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return sd, nil, "", err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return sd, nil, "", err
	}
	return sd, owner, sd.String(), nil
}

func daclACEs(sddl string) []string {
	start := strings.Index(sddl, "D:")
	if start < 0 {
		return nil
	}
	dacl := sddl[start+2:]
	if stop := strings.Index(dacl, "S:"); stop >= 0 {
		dacl = dacl[:stop]
	}
	var out []string
	for {
		open := strings.IndexByte(dacl, '(')
		if open < 0 {
			return out
		}
		closeAt := strings.IndexByte(dacl[open:], ')')
		if closeAt < 0 {
			return out
		}
		out = append(out, dacl[open+1:open+closeAt])
		dacl = dacl[open+closeAt+1:]
	}
}

func windowsAllowACE(kind string) bool {
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "A", "OA", "XA", "ZA":
		return true
	default:
		return false
	}
}

func windowsRightsMayWrite(rights string) bool {
	rights = strings.ToUpper(strings.TrimSpace(rights))
	if rights == "GR" || rights == "FR" || rights == "GRGX" || rights == "FRFX" || rights == "RC" {
		return false
	}
	// Our writer emits symbolic rights. Treat anything else conservatively: an
	// unfamiliar allow mask must not silently become a tamper-safe certificate.
	return true
}
