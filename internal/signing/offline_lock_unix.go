//go:build darwin || linux

// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"os"
	"path/filepath"
	"syscall"
)

func lockOfflineVault(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "offline-vault.lock"), os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- fixed lock name under dedicated operator-selected offline vault (CWE-22)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
