// SPDX-License-Identifier: MPL-2.0

//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"trstctl.com/clients/signing/internal/kspinfo"
)

// NTSTATUS values the configuration calls return for a registration that is
// already there or already gone.
const (
	statusObjectNameNotFound  = 0xC0000034
	statusObjectNameCollision = 0xC0000035
	statusNotFound            = 0xC0000225
)

type ntstatus uint32

func (s ntstatus) failed() bool   { return int32(s) < 0 }
func (s ntstatus) String() string { return fmt.Sprintf("NTSTATUS 0x%08X", uint32(s)) }

// cryptStrings is CRYPT_PROVIDERS and CRYPT_CONTEXT_FUNCTION_PROVIDERS: a
// count and an array of NUL-terminated UTF-16 names.
type cryptStrings struct {
	Count uint32
	Names **uint16
}

// ncryptProviderName is NCryptProviderName.
type ncryptProviderName struct {
	Name    *uint16
	Comment *uint16
}

// platform calls CNG's configuration functions in bcrypt.dll and ncrypt.dll,
// loaded from the system directory by absolute path.
type platform struct{}

var procGetSystemDirectory = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW")

func (platform) systemDirectory() (string, error) {
	buf := make([]uint16, syscall.MAX_PATH+1)
	n, _, err := procGetSystemDirectory.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		return "", fmt.Errorf("GetSystemDirectory: %w", err)
	}
	return syscall.UTF16ToString(buf[:n]), nil
}

func (p platform) proc(dll, name string) (*syscall.LazyProc, error) {
	dir, err := p.systemDirectory()
	if err != nil {
		return nil, err
	}
	proc := syscall.NewLazyDLL(filepath.Join(dir, dll)).NewProc(name)
	if err := proc.Find(); err != nil {
		return nil, fmt.Errorf("%s!%s: %w", dll, name, err)
	}
	return proc, nil
}

func (p platform) call(dll, name string, args ...uintptr) (ntstatus, error) {
	proc, err := p.proc(dll, name)
	if err != nil {
		return 0, err
	}
	r, _, _ := proc.Call(args...)
	return ntstatus(uint32(r)), nil // #nosec G115 -- NTSTATUS and SECURITY_STATUS are 32-bit values
}

func (p platform) register(image string) error {
	reg := newRegistration(image)
	name, function := utf16z(kspinfo.ProviderName), utf16z(keyStorageFunction)
	st, err := p.call("bcrypt.dll", "BCryptRegisterProvider",
		uintptr(unsafe.Pointer(&name[0])), cryptOverwrite, uintptr(unsafe.Pointer(&reg.provider)))
	runtime.KeepAlive(reg)
	if err != nil {
		return err
	}
	if st.failed() {
		return fmt.Errorf("BCryptRegisterProvider: %v (run elevated)", st)
	}
	st, err = p.call("bcrypt.dll", "BCryptAddContextFunctionProvider",
		cryptLocal, 0, ncryptKeyStorageInterface, uintptr(unsafe.Pointer(&function[0])), uintptr(unsafe.Pointer(&name[0])), cryptPriorityBottom)
	if err != nil {
		return err
	}
	if st.failed() && st != statusObjectNameCollision {
		return fmt.Errorf("BCryptAddContextFunctionProvider: %v", st)
	}
	return nil
}

func (p platform) unregister() error {
	name, function := utf16z(kspinfo.ProviderName), utf16z(keyStorageFunction)
	st, err := p.call("bcrypt.dll", "BCryptRemoveContextFunctionProvider",
		cryptLocal, 0, ncryptKeyStorageInterface, uintptr(unsafe.Pointer(&function[0])), uintptr(unsafe.Pointer(&name[0])))
	if err != nil {
		return err
	}
	if st.failed() && !gone(st) {
		return fmt.Errorf("BCryptRemoveContextFunctionProvider: %v (run elevated)", st)
	}
	if st, err = p.call("bcrypt.dll", "BCryptUnregisterProvider", uintptr(unsafe.Pointer(&name[0]))); err != nil {
		return err
	}
	if st.failed() && !gone(st) {
		return fmt.Errorf("BCryptUnregisterProvider: %v (run elevated)", st)
	}
	return nil
}

// wideString reads a NUL-terminated UTF-16 string CNG returned, bounded.
func wideString(p *uint16) string {
	if p == nil {
		return ""
	}
	var units []uint16
	for ptr := unsafe.Pointer(p); len(units) < 1024; ptr = unsafe.Add(ptr, 2) {
		u := *(*uint16)(ptr)
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return syscall.UTF16ToString(units)
}

func gone(st ntstatus) bool { return st == statusNotFound || st == statusObjectNameNotFound }

func (p platform) listed() (registered, storage bool, err error) {
	var size uint32
	var providers *cryptStrings
	st, err := p.call("bcrypt.dll", "BCryptEnumRegisteredProviders", uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&providers)))
	if err != nil {
		return false, false, err
	}
	if st.failed() {
		return false, false, fmt.Errorf("BCryptEnumRegisteredProviders: %v", st)
	}
	if providers != nil {
		for _, n := range unsafe.Slice(providers.Names, providers.Count) {
			registered = registered || wideString(n) == kspinfo.ProviderName
		}
		if _, err := p.call("bcrypt.dll", "BCryptFreeBuffer", uintptr(unsafe.Pointer(providers))); err != nil {
			return false, false, err
		}
	}
	var count uint32
	var list *ncryptProviderName
	st, err = p.call("ncrypt.dll", "NCryptEnumStorageProviders", uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&list)), 0)
	if err != nil {
		return false, false, err
	}
	if st.failed() {
		return false, false, fmt.Errorf("NCryptEnumStorageProviders: %v", st)
	}
	if list != nil {
		for _, n := range unsafe.Slice(list, count) {
			storage = storage || wideString(n.Name) == kspinfo.ProviderName
		}
		if _, err := p.call("ncrypt.dll", "NCryptFreeBuffer", uintptr(unsafe.Pointer(list))); err != nil {
			return false, false, err
		}
	}
	return registered, storage, nil
}
