// SPDX-License-Identifier: BUSL-1.1
//go:build linux || windows

package secret

// The ordinary Buffer allocator already uses the protected OS path on these
// platforms: mmap/mlock/MADV_DONTDUMP or VirtualAlloc/VirtualLock.
func allocProtected(size int) ([]byte, error) { return alloc(size) }
func freeProtected(region []byte) error       { return free(region) }
