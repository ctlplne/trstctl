// SPDX-License-Identifier: MPL-2.0

//go:build linux

package secret

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// alloc returns a dedicated, page-aligned region of at least size bytes that is
// locked into RAM (mlock) and excluded from core dumps (MADV_DONTDUMP). Using a
// fresh mmap mapping (rather than a heap slice) guarantees page alignment, which
// madvise requires, and keeps the secret off the Go heap and away from other
// objects' pages.
func alloc(size int) ([]byte, error) {
	n := roundUpToPage(size)
	region, err := unix.Mmap(-1, 0, n, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, fmt.Errorf("secret: mmap: %w", err)
	}
	if err := unix.Mlock(region); err != nil {
		_ = unix.Munmap(region)
		return nil, fmt.Errorf("secret: mlock: %w", err)
	}
	if err := unix.Madvise(region, unix.MADV_DONTDUMP); err != nil {
		_ = unix.Munlock(region)
		_ = unix.Munmap(region)
		return nil, fmt.Errorf("secret: madvise dontdump: %w", err)
	}
	return region, nil
}

// free re-enables dumping (best effort), unlocks, and unmaps a region from alloc.
func free(region []byte) error {
	if len(region) == 0 {
		return nil
	}
	_ = unix.Madvise(region, unix.MADV_DODUMP)
	if err := unix.Munlock(region); err != nil {
		_ = unix.Munmap(region)
		return err
	}
	return unix.Munmap(region)
}

func roundUpToPage(n int) int {
	page := unix.Getpagesize()
	if page <= 0 {
		return n
	}
	if r := n % page; r != 0 {
		return n + (page - r)
	}
	return n
}
