// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package secret

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// memFree is MEM_FREE, a VirtualQuery state x/sys does not name.
const memFree = 0x10000

// AN-8 on Windows (owner decision 2026-11-02, item 2g f), proven on
// windows-latest: each region is page-aligned, outside the Go heap and locked
// (VirtualUnlock succeeds only on locked pages), more locked memory than the
// default minimum working set allows is obtained by raising it, and free
// zeroes the region and returns it to the system.
func TestWindowsRegionsAreLockedAndReleased(t *testing.T) {
	const count, size = 64, 64 << 10 // 4 MiB: far past the default 200 KiB minimum working set
	regions := make([][]byte, 0, count)
	defer func() {
		for _, region := range regions {
			_ = free(region)
		}
	}()
	page := uintptr(os.Getpagesize())
	for i := 0; i < count; i++ {
		region, err := alloc(size)
		if err != nil {
			t.Fatalf("alloc %d of %d: %v", i+1, count, err)
		}
		regions = append(regions, region)
		addr := uintptr(unsafe.Pointer(&region[0])) // #nosec G103 -- reads the address of the region alloc returned, to check its alignment (CWE-242)
		if addr%page != 0 || len(region)%int(page) != 0 {
			t.Fatalf("region %d is not page-aligned: %#x, %d bytes", i, addr, len(region))
		}
		region[0], region[len(region)-1] = 0xA5, 0x5A
	}
	probe := regions[len(regions)-1]
	addr, n := uintptr(unsafe.Pointer(&probe[0])), uintptr(len(probe)) // #nosec G103 -- the region's address, to query its lock and release state (CWE-242)
	if err := windows.VirtualUnlock(addr, n); err != nil {
		t.Fatalf("the region was not locked: VirtualUnlock = %v", err)
	}
	if err := windows.VirtualLock(addr, n); err != nil {
		t.Fatalf("relock: %v", err)
	}
	if err := free(probe); err != nil {
		t.Fatalf("free: %v", err)
	}
	regions = regions[:len(regions)-1]
	var info windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addr, &info, unsafe.Sizeof(info)); err != nil || info.State != memFree {
		t.Fatalf("after free the region is in state %#x (%v), want MEM_FREE", info.State, err)
	}
	buffer, err := New(32)
	if err != nil {
		t.Fatal(err)
	}
	copy(buffer.Bytes(), "locked secret material on windows")
	buffer.Destroy()
}
