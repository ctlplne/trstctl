// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package secret

import (
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"sync"
	"unsafe"
)

// LockNativeWindowsBuffer locks an exclusively owned native allocation, such as
// an Automation BSTR that must be freed by its native allocator. The returned
// release wipes the bytes before unlocking and is idempotent. It does not free
// memory. The caller must serialize private native heap allocations whose pages
// can overlap; VirtualUnlock does not count individual allocations on a page.
func LockNativeWindowsBuffer(raw []byte) (func() error, error) {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return nil, errors.New("secret: native Windows buffer exceeds bound")
	}
	address := uintptr(unsafe.Pointer(&raw[0])) // #nosec G103 -- caller-owned native allocation remains live through release and native free; only its bounded bytes are borrowed (CWE-242)
	if err := lockRegion(address, uintptr(len(raw))); err != nil {
		return nil, err
	}
	var once sync.Once
	var released error
	return func() error {
		once.Do(func() {
			Wipe(raw)
			released = windows.VirtualUnlock(address, uintptr(len(raw)))
			runtime.KeepAlive(raw)
		})
		return released
	}, nil
}
