// SPDX-License-Identifier: BUSL-1.1

//go:build !linux

package cli

// protectLauncherProcess reports that this platform cannot enforce Linux's
// process inspection boundary for a command launched as the same OS user.
func protectLauncherProcess() (bool, error) { return false, nil }
