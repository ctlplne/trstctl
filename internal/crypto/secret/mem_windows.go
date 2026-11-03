// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package secret

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// workingSetMu serializes raising the process's working-set limits, a
// read-modify-write two allocations could otherwise race on.
var workingSetMu sync.Mutex

// alloc returns a dedicated, page-aligned region of at least size bytes,
// committed with VirtualAlloc and locked into the process's working set with
// VirtualLock, so the secret stays off the Go heap and out of the page file
// (AN-8 on Windows; owner decision 2026-11-02, item 2g f). Windows lets a
// process lock only up to its minimum working set: when VirtualLock reports
// ERROR_WORKING_SET_QUOTA the limits are raised by the region's size and the
// lock retried once. Any other failure releases the region and fails closed;
// no unlocked buffer is handed out. (Windows writes no core dump of a
// process unless one is configured; the region is still zeroed on free.)
func alloc(size int) ([]byte, error) {
	n := uintptr(roundUpToPage(size))
	addr, err := windows.VirtualAlloc(0, n, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("secret: VirtualAlloc: %w", err)
	}
	if err := lockRegion(addr, n); err != nil {
		_ = windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return nil, err
	}
	return unsafe.Slice((*byte)(unsafe.Add(nil, addr)), n), nil // #nosec G103 -- VirtualAlloc's committed region, outside the Go heap, released only by free (CWE-242)
}

func lockRegion(addr, n uintptr) error {
	err := windows.VirtualLock(addr, n)
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_WORKING_SET_QUOTA) {
		return fmt.Errorf("secret: VirtualLock: %w", err)
	}
	if err := growWorkingSet(n); err != nil {
		return fmt.Errorf("secret: VirtualLock hit the working-set quota and raising it failed: %w", err)
	}
	if err := windows.VirtualLock(addr, n); err != nil {
		return fmt.Errorf("secret: VirtualLock after raising the working set: %w", err)
	}
	return nil
}

// growWorkingSet raises the process's minimum and maximum working set by n
// plus a few pages of locking overhead, keeping its hard-limit flags.
func growWorkingSet(n uintptr) error {
	workingSetMu.Lock()
	defer workingSetMu.Unlock()
	process := windows.CurrentProcess()
	var minimum, maximum uintptr
	var flags uint32
	// x/sys drops this call's result; zero limits mean it failed, and setting
	// limits from zero could shrink the working set.
	windows.GetProcessWorkingSetSizeEx(process, &minimum, &maximum, &flags)
	if minimum == 0 || maximum == 0 {
		return errors.New("secret: could not read the process's working-set limits")
	}
	grow := n + 16*uintptr(os.Getpagesize())
	return windows.SetProcessWorkingSetSizeEx(process, minimum+grow, maximum+grow, flags)
}

// free zeroes the region, unlocks it and releases it to the system.
func free(region []byte) error {
	if len(region) == 0 {
		return nil
	}
	Wipe(region)
	addr := uintptr(unsafe.Pointer(&region[0])) // #nosec G103 -- the address VirtualAlloc returned for this region (CWE-242)
	unlockErr := windows.VirtualUnlock(addr, uintptr(len(region)))
	if err := windows.VirtualFree(addr, 0, windows.MEM_RELEASE); err != nil {
		return err
	}
	return unlockErr
}

func roundUpToPage(n int) int {
	page := os.Getpagesize()
	if page <= 0 {
		return n
	}
	if r := n % page; r != 0 {
		return n + (page - r)
	}
	return n
}
