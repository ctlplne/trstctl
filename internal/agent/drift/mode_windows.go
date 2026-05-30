//go:build windows

package drift

import (
	"os"

	"golang.org/x/sys/windows"
)

// permissionDetectionSupported is true on Windows: access is read from the file's
// DACL (Go's FileMode bits are not the access-control mechanism here).
const permissionDetectionSupported = true

// permissionDrifted reports whether a Restricted credential's DACL grants access
// to a broad principal (Everyone, Authenticated Users, or Users) — the Windows
// loosening that matters for a sensitive file. The declared POSIX Mode is not
// consulted on Windows. If the security descriptor cannot be read, no drift is
// reported rather than a false alarm.
func permissionDrifted(path string, _ os.FileInfo, w Watched) (bool, string) {
	if !w.Restricted {
		return false, ""
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, ""
	}
	if name, broad := sddlAllowsBroad(sd.String()); broad {
		return true, "DACL grants access to broad principal " + name
	}
	return false, ""
}
