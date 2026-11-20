// SPDX-License-Identifier: BUSL-1.1

// Package privatesocket validates directories used for local identity sockets.
// The directory is the access boundary while a Unix socket is being bound.
package privatesocket

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// EnsureDirectory creates one missing socket directory with mode 0700, or
// verifies an existing one. It never changes permissions on an existing path.
// Every ancestor must be owned by root or this process and must prevent other
// users from replacing the next path component. A root-owned sticky directory
// such as the system temporary directory can safely contain a private child.
func EnsureDirectory(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("socket directory must be an absolute clean path")
	}
	parent := filepath.Dir(dir)
	if err := verifyAncestors(parent); err != nil {
		return err
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create socket directory: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("inspect socket directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect socket directory: %w", err)
	}
	uid, err := ownerUID(info)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || uid != os.Geteuid() {
		return fmt.Errorf("socket directory must be a 0700 directory owned by this process: %s", dir)
	}
	return nil
}

// OwnedByProcess reports whether an existing socket path belongs to the uid
// that will serve it. A platform without a verifiable Unix uid fails closed.
func OwnedByProcess(info os.FileInfo) (bool, error) {
	uid, err := ownerUID(info)
	return uid == os.Geteuid(), err
}

func verifyAncestors(dir string) error {
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("inspect socket directory ancestor %s: %w", dir, err)
		}
		uid, err := ownerUID(info)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (uid != 0 && uid != os.Geteuid()) {
			return fmt.Errorf("socket directory ancestor is not trusted: %s", dir)
		}
		if info.Mode().Perm()&0o022 != 0 && (info.Mode()&os.ModeSticky == 0 || uid != 0) {
			return fmt.Errorf("socket directory ancestor is writable by another user: %s", dir)
		}
		next := filepath.Dir(dir)
		if next == dir {
			return nil
		}
		dir = next
	}
}
