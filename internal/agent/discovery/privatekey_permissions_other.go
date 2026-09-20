// SPDX-License-Identifier: BUSL-1.1

//go:build !unix && !windows

package discovery

import (
	"os"
	"runtime"
)

func privateKeyPermissionState(_ string, _ os.FileInfo) (bool, map[string]string) {
	return false, map[string]string{"permission_model": "unsupported", "platform": runtime.GOOS}
}
