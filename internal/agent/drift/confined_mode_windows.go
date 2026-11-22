// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package drift

import (
	"os"

	"golang.org/x/sys/windows"
)

// The served path checks the DACL on the rooted descriptor. A named ACL lookup
// could follow a tenant-chosen symlink after the bounded content read.
func permissionDriftedConfined(root *os.Root, rel string, _ os.FileInfo, w Watched) (bool, string) {
	if !w.Restricted {
		return false, ""
	}
	file, err := root.Open(rel)
	if err != nil {
		return false, ""
	}
	defer func() { _ = file.Close() }()
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, ""
	}
	if name, broad := sddlAllowsBroad(sd.String()); broad {
		return true, "DACL grants access to broad principal " + name
	}
	return false, ""
}
