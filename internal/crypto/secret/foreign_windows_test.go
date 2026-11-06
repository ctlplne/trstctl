// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package secret

import (
	"golang.org/x/sys/windows"
	"sync"
	"testing"
	"unsafe"
)

func TestNativeWindowsForeignBufferA267(t *testing.T) {
	if _, err := LockNativeWindowsBuffer(nil); err == nil {
		t.Fatal("empty native buffer admitted")
	}
	address, err := windows.VirtualAlloc(0, 4096, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := windows.VirtualFree(address, 0, windows.MEM_RELEASE); err != nil {
			t.Error(err)
		}
	}()
	raw := unsafe.Slice((*byte)(unsafe.Add(nil, address)), 4096) // #nosec G103 -- exact owned VirtualAlloc page, freed only after wipe/unlock assertions (CWE-242)
	release, err := LockNativeWindowsBuffer(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 0x5a
	}
	type workingSetInfo struct{ Address, Flags uintptr }
	info := workingSetInfo{Address: address}
	ok, _, _ := windows.NewLazySystemDLL("psapi.dll").NewProc("QueryWorkingSetEx").Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)) // #nosec G103 -- exact PSAPI working-set output for the live owned allocation and current process (CWE-242)
	if ok == 0 || info.Flags&1 == 0 || info.Flags&(1<<22) == 0 {
		t.Fatal("native private buffer was not locked in physical memory")
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := release(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for _, value := range raw {
		if value != 0 {
			t.Fatal("native buffer release did not wipe before unlock/free")
		}
	}
	t.Log("A267_WINDOWS_NATIVE_BUFFER_OK")
}
