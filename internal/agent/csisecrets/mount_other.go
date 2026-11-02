// SPDX-License-Identifier: BUSL-1.1

//go:build !linux

package csisecrets

import "errors"

// SystemMounter stands in on systems without the Linux mount syscalls: the
// node plugin runs on Linux nodes only.
type SystemMounter struct{}

var errLinuxOnly = errors.New("csisecrets: secret volumes need a Linux node")

// MountTmpfs refuses: there is no memory filesystem to mount here.
func (SystemMounter) MountTmpfs(string, int) error { return errLinuxOnly }

// IsMountPoint refuses.
func (SystemMounter) IsMountPoint(string) (bool, error) { return false, errLinuxOnly }

// Unmount refuses.
func (SystemMounter) Unmount(string) error { return errLinuxOnly }
