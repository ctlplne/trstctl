// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package drift

import "os"

func permissionDriftedConfined(_ *os.Root, _ string, info os.FileInfo, w Watched) (bool, string) {
	return permissionDrifted("", info, w)
}
