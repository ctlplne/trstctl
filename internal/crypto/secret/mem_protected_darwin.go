// SPDX-License-Identifier: BUSL-1.1
//go:build darwin

package secret

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Darwin has no MADV_DONTDUMP flag. A protected verifier allocation therefore
// makes process core files impossible before it exposes any plaintext.
func allocProtected(size int) ([]byte, error) {
	var core unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &core); err != nil {
		return nil, fmt.Errorf("%w: read core limit: %v", ErrProtectedMemory, err)
	}
	if core.Cur != 0 || core.Max != 0 {
		if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
			return nil, fmt.Errorf("%w: disable core files: %v", ErrProtectedMemory, err)
		}
	}
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &core); err != nil || core.Cur != 0 || core.Max != 0 {
		return nil, fmt.Errorf("%w: core-file exclusion is unverified: %v", ErrProtectedMemory, err)
	}
	page := os.Getpagesize()
	if page <= 0 || size > int(^uint(0)>>1)-page {
		return nil, fmt.Errorf("%w: invalid page size", ErrProtectedMemory)
	}
	length := size
	if remainder := length % page; remainder != 0 {
		length += page - remainder
	}
	region, err := unix.Mmap(-1, 0, length, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, fmt.Errorf("%w: mmap: %v", ErrProtectedMemory, err)
	}
	if err := unix.Mlock(region); err != nil {
		_ = unix.Munmap(region)
		return nil, fmt.Errorf("%w: mlock: %v", ErrProtectedMemory, err)
	}
	return region, nil
}

func freeProtected(region []byte) error {
	if len(region) == 0 {
		return nil
	}
	Wipe(region)
	unlockErr := unix.Munlock(region)
	unmapErr := unix.Munmap(region)
	if unlockErr != nil {
		return unlockErr
	}
	return unmapErr
}
