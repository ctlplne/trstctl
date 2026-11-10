// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package secretrender

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// restrictPath gives a rendered file an explicit, protected DACL derived from
// its mode before any content is written (A238-L10). Without it a new file
// inherits its directory's DACL, so the mode decided nothing about who reads a
// secret: any principal the directory lets read could read it. The file's
// owner (the agent's user) and SYSTEM get full control, as the owner and root
// can on Unix; the group bits grant read to the agent's primary group and the
// other bits to Authenticated Users. Inheritance is cut, so nothing else reads
// the file whatever the directory allows.
func restrictPath(path string, mode os.FileMode) error {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("secretrender: read the agent's user: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("secretrender: SYSTEM's SID: %w", err)
	}
	grant := func(sid *windows.SID, access windows.ACCESS_MASK, kind windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: access, AccessMode: windows.GRANT_ACCESS, Inheritance: windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: kind, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		}
	}
	entries := []windows.EXPLICIT_ACCESS{
		grant(user.User.Sid, windows.GENERIC_ALL, windows.TRUSTEE_IS_USER),
		grant(system, windows.GENERIC_ALL, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}
	if mode&0o040 != 0 {
		group, err := token.GetTokenPrimaryGroup()
		if err != nil {
			return fmt.Errorf("secretrender: read the agent's primary group: %w", err)
		}
		entries = append(entries, grant(group.PrimaryGroup, windows.GENERIC_READ, windows.TRUSTEE_IS_GROUP))
	}
	if mode&0o004 != 0 {
		authenticated, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
		if err != nil {
			return fmt.Errorf("secretrender: Authenticated Users' SID: %w", err)
		}
		entries = append(entries, grant(authenticated, windows.GENERIC_READ, windows.TRUSTEE_IS_WELL_KNOWN_GROUP))
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("secretrender: build the file's DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("secretrender: set the file's DACL: %w", err)
	}
	return nil
}
