// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package csisecrets

import (
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// SystemMounter mounts through the Linux mount syscalls; the plugin needs
// CAP_SYS_ADMIN for them, which is why its container is privileged.
type SystemMounter struct{}

// MountTmpfs mounts a memory filesystem that can hold no device files, no
// set-id programs and nothing executable.
func (SystemMounter) MountTmpfs(target string, size int) error {
	return unix.Mount("tmpfs", target, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC,
		"mode=0750,size="+strconv.Itoa(size))
}

// IsMountPoint reports whether target is on a different filesystem from its
// parent directory.
func (SystemMounter) IsMountPoint(target string) (bool, error) {
	var self, parent unix.Stat_t
	if err := unix.Stat(target, &self); err != nil {
		return false, err
	}
	if err := unix.Stat(filepath.Dir(target), &parent); err != nil {
		return false, err
	}
	return self.Dev != parent.Dev || self.Ino == parent.Ino, nil
}

// Unmount detaches the filesystem at target.
func (SystemMounter) Unmount(target string) error { return unix.Unmount(target, 0) }
