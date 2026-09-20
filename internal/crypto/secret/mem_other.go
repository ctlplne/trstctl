// SPDX-License-Identifier: BUSL-1.1

//go:build !linux

package secret

// On non-Linux platforms, locking and core-dump exclusion are best-effort
// no-ops: the buffer is an ordinary heap allocation that is still zeroized on
// Destroy. Linux is the production target (see mem_linux.go).

func alloc(size int) ([]byte, error) {
	return make([]byte, size), nil
}

func free(region []byte) error {
	_ = region
	return nil
}
