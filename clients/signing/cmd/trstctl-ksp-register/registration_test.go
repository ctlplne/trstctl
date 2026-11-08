// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"trstctl.com/clients/signing/internal/kspinfo"
)

func readWide(p *uint16) string {
	var units []uint16
	for ptr := unsafe.Pointer(p); *(*uint16)(ptr) != 0; ptr = unsafe.Add(ptr, 2) {
		units = append(units, *(*uint16)(ptr))
	}
	return string(utf16.Decode(units))
}

// TestRegistrationHasTheLayoutBCryptRegisterProviderReads checks the
// registration against bcrypt.h's structures on 64-bit Windows, field by
// field, and its content: one user-mode image, trstctl-ksp.dll, implementing
// the key storage interface's KEY_STORAGE function on this machine, with no
// kernel-mode image and no aliases.
func TestRegistrationHasTheLayoutBCryptRegisterProviderReads(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the provider is built for 64-bit Windows")
	}
	var iface cryptInterfaceReg
	var image cryptImageReg
	var provider cryptProviderReg
	for field, got := range map[string][2]uintptr{
		"CRYPT_INTERFACE_REG.dwInterface":    {unsafe.Offsetof(iface.Interface), 0},
		"CRYPT_INTERFACE_REG.dwFlags":        {unsafe.Offsetof(iface.Flags), 4},
		"CRYPT_INTERFACE_REG.cFunctions":     {unsafe.Offsetof(iface.Functions), 8},
		"CRYPT_INTERFACE_REG.rgpszFunctions": {unsafe.Offsetof(iface.Names), 16},
		"sizeof(CRYPT_INTERFACE_REG)":        {unsafe.Sizeof(iface), 24},
		"CRYPT_IMAGE_REG.pszImage":           {unsafe.Offsetof(image.Image), 0},
		"CRYPT_IMAGE_REG.cInterfaces":        {unsafe.Offsetof(image.Interfaces), 8},
		"CRYPT_IMAGE_REG.rgpInterfaces":      {unsafe.Offsetof(image.List), 16},
		"sizeof(CRYPT_IMAGE_REG)":            {unsafe.Sizeof(image), 24},
		"CRYPT_PROVIDER_REG.cAliases":        {unsafe.Offsetof(provider.Aliases), 0},
		"CRYPT_PROVIDER_REG.rgpszAliases":    {unsafe.Offsetof(provider.AliasList), 8},
		"CRYPT_PROVIDER_REG.pUM":             {unsafe.Offsetof(provider.UserMode), 16},
		"CRYPT_PROVIDER_REG.pKM":             {unsafe.Offsetof(provider.KernelMode), 24},
		"sizeof(CRYPT_PROVIDER_REG)":         {unsafe.Sizeof(provider), 32},
	} {
		if got[0] != got[1] {
			t.Errorf("%s at %d, want %d", field, got[0], got[1])
		}
	}

	reg := newRegistration(kspinfo.ImageName)
	if reg.provider.Aliases != 0 || reg.provider.AliasList != nil || reg.provider.KernelMode != nil || reg.provider.UserMode == nil {
		t.Fatalf("provider registration %+v, want one user-mode image and nothing else", reg.provider)
	}
	um := reg.provider.UserMode
	if got := readWide(um.Image); got != "trstctl-ksp.dll" {
		t.Errorf("image %q", got)
	}
	ifaces := unsafe.Slice(um.List, um.Interfaces)
	if len(ifaces) != 1 {
		t.Fatalf("%d interfaces, want 1", len(ifaces))
	}
	if ifaces[0].Interface != 0x00010001 || ifaces[0].Flags != 0x1 || ifaces[0].Functions != 1 {
		t.Errorf("interface %+v, want NCRYPT_KEY_STORAGE_INTERFACE, CRYPT_LOCAL, one function", *ifaces[0])
	}
	if got := readWide(unsafe.Slice(ifaces[0].Names, ifaces[0].Functions)[0]); got != "KEY_STORAGE" {
		t.Errorf("function %q, want KEY_STORAGE", got)
	}
}

// fakeCNG records what the commands asked of CNG.
type fakeCNG struct {
	dir                 string
	image               string
	registered, storage bool
	unregistered        bool
	fail                error
}

func (f *fakeCNG) systemDirectory() (string, error) { return f.dir, nil }
func (f *fakeCNG) register(image string) error {
	if f.fail != nil {
		return f.fail
	}
	f.image, f.registered, f.storage = image, true, true
	return nil
}
func (f *fakeCNG) unregister() error {
	f.unregistered, f.registered, f.storage = true, false, false
	return nil
}
func (f *fakeCNG) listed() (bool, bool, error) { return f.registered, f.storage, nil }

// TestInstallStatusAndUninstall checks the commands against a stand-in CNG:
// install refuses a file that is not a DLL, copies the provider into the
// system directory and registers it by file name; status exits 0 only while
// CNG and NCrypt both list it; uninstall removes the registration and the
// copy; bad arguments print the usage; off Windows every command fails.
func TestInstallStatusAndUninstall(t *testing.T) {
	work, system := t.TempDir(), t.TempDir()
	dll := filepath.Join(work, "trstctl-ksp.dll")
	if err := os.WriteFile(dll, []byte("MZ provider image"), 0o600); err != nil {
		t.Fatal(err)
	}
	notDLL := filepath.Join(work, "notes.txt")
	if err := os.WriteFile(notDLL, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &fakeCNG{dir: system}
	var out, errOut bytes.Buffer
	if code := run([]string{"install", notDLL}, &out, &errOut, c); code != 1 || !strings.Contains(errOut.String(), "is not a Windows DLL") || c.registered {
		t.Fatalf("install of a non-DLL = %d %q", code, errOut.String())
	}
	if code := run([]string{"status"}, &out, &errOut, c); code != 1 {
		t.Fatalf("status before install = %d, want 1", code)
	}
	if code := run([]string{"install", dll}, &out, &errOut, c); code != 0 {
		t.Fatalf("install = %d: %s", code, errOut.String())
	}
	copied, err := os.ReadFile(filepath.Join(system, "trstctl-ksp.dll"))
	if err != nil || string(copied) != "MZ provider image" || c.image != "trstctl-ksp.dll" {
		t.Fatalf("install copied %q (%v) and registered image %q", copied, err, c.image)
	}
	out.Reset()
	if code := run([]string{"status"}, &out, &errOut, c); code != 0 || !strings.Contains(out.String(), "registered with CNG: true; listed by NCrypt: true") {
		t.Fatalf("status after install = %d %q", code, out.String())
	}
	if code := run([]string{"uninstall"}, &out, &errOut, c); code != 0 || !c.unregistered {
		t.Fatalf("uninstall = %d: %s", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(system, "trstctl-ksp.dll")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uninstall left the DLL: %v", err)
	}
	if code := run([]string{"status"}, &out, &errOut, c); code != 1 {
		t.Fatalf("status after uninstall = %d, want 1", code)
	}
	c.fail = errors.New("BCryptRegisterProvider: NTSTATUS 0xC0000022 (run elevated)")
	errOut.Reset()
	if code := run([]string{"install", dll}, &out, &errOut, c); code != 1 || !strings.Contains(errOut.String(), "run elevated") {
		t.Fatalf("a refused registration = %d %q", code, errOut.String())
	}
	for _, args := range [][]string{nil, {"install"}, {"status", "x"}, {"remove"}} {
		errOut.Reset()
		if code := run(args, &out, &errOut, c); code != 2 || !strings.Contains(errOut.String(), "usage:") {
			t.Errorf("%q = %d %q, want the usage", args, code, errOut.String())
		}
	}
	if runtime.GOOS != "windows" {
		errOut.Reset()
		if code := run([]string{"status"}, &out, &errOut, platform{}); code != 1 || !strings.Contains(errOut.String(), "run it on Windows") {
			t.Errorf("status off Windows = %d %q, want a refusal", code, errOut.String())
		}
	}
}
