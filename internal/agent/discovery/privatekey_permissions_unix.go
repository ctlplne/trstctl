// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package discovery

import (
	"fmt"
	"os"
	"runtime"
)

func privateKeyPermissionState(_ string, info os.FileInfo) (bool, map[string]string) {
	return info.Mode().Perm()&0o077 == 0, map[string]string{
		"file_mode":        fmt.Sprintf("%04o", info.Mode().Perm()),
		"permission_model": "posix_mode",
		"platform":         runtime.GOOS,
	}
}
