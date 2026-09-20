// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package discovery

import (
	"os"

	"trstctl.com/trstctl/internal/crypto/secretfile"
)

func privateKeyPermissionState(path string, _ os.FileInfo) (bool, map[string]string) {
	restricted, err := secretfile.IsPrivate(path)
	metadata := map[string]string{"permission_model": "windows_dacl", "platform": "windows"}
	if err != nil {
		metadata["permission_check"] = "unavailable"
		return false, metadata
	}
	return restricted, metadata
}
