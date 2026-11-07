//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import (
	"context"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unsafe"
)

type fixtureUser1 struct {
	Name, Password         *uint16
	PasswordAge, Privilege uint32
	Home, Comment          *uint16
	Flags                  uint32
	Script                 *uint16
}

func TestNativeWindowsLocalAdministratorInventoryA268(t *testing.T) {
	if os.Getenv("TRSTCTL_A268_WINDOWS_INVENTORY") != "1" {
		t.Skip("owned native Windows SAM fixture only")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	before, err := New().Inventory(ctx)
	if err != nil {
		t.Fatal("native SAM inventory unavailable", err)
	}
	name := "ctl268_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	wideName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	random, err := crypto.RandomBytes(24)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(random)
	password, err := secret.New(2 * (3 + 2*len(random) + 1))
	if err != nil {
		t.Fatal(err)
	}
	defer password.Destroy()
	raw := password.Bytes()
	raw[0] = 'A'
	raw[2] = 'b'
	raw[4] = '3'
	const alphabet = "0123456789abcdef"
	for i, value := range random {
		raw[2*(3+2*i)] = alphabet[value>>4]
		raw[2*(4+2*i)] = alphabet[value&15]
	}
	secret.Wipe(random)
	widePassword := (*uint16)(unsafe.Pointer(&raw[0])) // #nosec G103 -- aligned locked UTF-16 password buffer, NUL-terminated, wiped and destroyed after synchronous owned fixture calls (CWE-242)
	fields := fixtureUser1{Name: wideName, Password: widePassword, Privilege: 1, Flags: 0x201}
	var parameter uint32
	status, _, _ := netapi.NewProc("NetUserAdd").Call(0, 1, uintptr(unsafe.Pointer(&fields)), uintptr(unsafe.Pointer(&parameter))) // #nosec G103 -- exact USER_INFO_1 ABI for one uniquely named owned fixture; password remains in a locked byte buffer (CWE-242)
	runtime.KeepAlive(password)
	if status != 0 {
		t.Fatal("owned account creation refused", status)
	}
	var ownedSID *windows.SID
	var alias *uint16
	added := false
	t.Cleanup(func() {
		if added && ownedSID != nil {
			membership := struct{ SID *windows.SID }{SID: ownedSID}
			result, _, _ := netapi.NewProc("NetLocalGroupDelMembers").Call(0, uintptr(unsafe.Pointer(alias)), 0, uintptr(unsafe.Pointer(&membership)), 1) // #nosec G103 -- removes only the exact owned SID membership created by this fixture (CWE-242)
			if result != 0 {
				t.Error("owned administrator membership cleanup failed", result)
			}
		}
		current, _, _, lookupErr := windows.LookupSID("", name)
		if ownedSID == nil || lookupErr != nil || current.String() != ownedSID.String() {
			t.Error("owned account identity changed; refusing name-only cleanup")
			return
		}
		result, _, _ := netapi.NewProc("NetUserDel").Call(0, uintptr(unsafe.Pointer(wideName))) // #nosec G103 -- exact newly created account name after current SID equality check; no wildcard or pre-existing account deletion (CWE-242)
		if result != 0 {
			t.Error("owned account cleanup failed", result)
		}
	})
	ownedSID, _, _, err = windows.LookupSID("", name)
	if err != nil {
		t.Fatal(err)
	}
	if !localSID(before.Machine.SID, ownedSID.String()) {
		t.Fatal("fixture is not a local SAM account")
	}
	builtin, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		t.Fatal(err)
	}
	aliasName, _, _, err := builtin.LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	alias, err = windows.UTF16PtrFromString(aliasName)
	if err != nil {
		t.Fatal(err)
	}
	membership := struct{ SID *windows.SID }{SID: ownedSID}
	status, _, _ = netapi.NewProc("NetLocalGroupAddMembers").Call(0, uintptr(unsafe.Pointer(alias)), 0, uintptr(unsafe.Pointer(&membership)), 1) // #nosec G103 -- fixed local alias and exact owned SID, one membership only (CWE-242)
	if status != 0 {
		t.Fatal("owned administrator membership refused", status)
	}
	added = true
	proveLogin := func() {
		t.Helper()
		domain, e := windows.UTF16PtrFromString(".")
		if e != nil {
			t.Fatal(e)
		}
		var token windows.Token
		ok, _, callErr := windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW").Call(uintptr(unsafe.Pointer(wideName)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(widePassword)), 2, 0, uintptr(unsafe.Pointer(&token))) // #nosec G103 -- one correct-password local fixture login; locked password pointer is never converted to a string or argv (CWE-242)
		runtime.KeepAlive(password)
		if ok == 0 {
			t.Fatal("owned local login failed", callErr)
		}
		defer func() { _ = token.Close() }()
		user, e := token.GetTokenUser()
		if e != nil || user.User.Sid.String() != ownedSID.String() {
			t.Fatal("native login returned a different identity", e)
		}
	}
	proveLogin()
	result, err := New().Inventory(ctx)
	if err != nil {
		t.Fatal("native local inventory incomplete", err)
	}
	found := false
	for _, account := range result.Accounts {
		if account.SID == ownedSID.String() {
			found = account.Name == name && account.Enabled && !account.Locked && account.PasswordRequired
		}
	}
	if !found || result.Machine != before.Machine {
		t.Fatal("owned native account or machine binding missing")
	}
	proveLogin()
	t.Log("A268_WINDOWS_LOCAL_INVENTORY_OK: exact local SAM SID, localized administrator alias, owned public account flags; correct login before and after read; rotation remains a separate proof")
}
