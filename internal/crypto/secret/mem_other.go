// SPDX-License-Identifier: BUSL-1.1

//go:build !linux && !windows

package secret

// On platforms other than Linux and Windows, locking and core-dump exclusion
// are best-effort no-ops: the buffer is an ordinary heap allocation that is
// still zeroized on Destroy. Linux (mem_linux.go) and Windows (mem_windows.go)
// lock it.

func alloc(size int) ([]byte, error) {
	return make([]byte, size), nil
}

func free(region []byte) error {
	_ = region
	return nil
}
