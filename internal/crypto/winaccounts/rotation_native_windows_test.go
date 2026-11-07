//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import (
	"context"
	"github.com/google/uuid"
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

func ownedRotationAccount(t *testing.T, ctx context.Context, machine Machine, suffix string) (RotationBinding, *secret.Buffer) {
	t.Helper()
	name := "ctlr_" + suffix + strconv.FormatInt(time.Now().UnixNano(), 36)
	if !validName(name) {
		t.Fatal("owned fixture name exceeded native policy")
	}
	publicName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	draw, err := crypto.RandomAccountPassword(32)
	if err != nil {
		t.Fatal(err)
	}
	password, err := secret.NewFrom(draw)
	secret.Wipe(draw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(password.Destroy)
	wide, err := lockedPasswordUTF16(password.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	fields := fixtureUser1{Name: publicName, Password: (*uint16)(unsafe.Pointer(&wide.Bytes()[0])), Privilege: 1, Flags: 0x201} // #nosec G103 -- live aligned locked UTF-16 password for one synchronous owned USER_INFO_1 fixture creation (CWE-242)
	var parameter uint32
	code, _, _ := netapi.NewProc("NetUserAdd").Call(0, 1, uintptr(unsafe.Pointer(&fields)), uintptr(unsafe.Pointer(&parameter))) // #nosec G103 -- local-only uniquely named test user; locked secret never becomes a string, file or argv (CWE-242)
	runtime.KeepAlive(wide)
	wide.Destroy()
	if code != 0 {
		t.Fatal("owned rotation account creation refused", code)
	}
	var sid *windows.SID
	var group *uint16
	added := false
	t.Cleanup(func() {
		if added && sid != nil {
			member := struct{ SID *windows.SID }{sid}
			result, _, _ := netapi.NewProc("NetLocalGroupDelMembers").Call(0, uintptr(unsafe.Pointer(group)), 0, uintptr(unsafe.Pointer(&member)), 1) // #nosec G103 -- removes only the exact owned SID membership this fixture added (CWE-242)
			if result != 0 {
				t.Error("owned rotation membership cleanup failed", result)
			}
		}
		current, _, _, err := windows.LookupSID("", name)
		if err != nil || sid == nil || current.String() != sid.String() {
			t.Error("owned fixture identity changed; refusing name-only deletion")
			return
		}
		result, _, _ := netapi.NewProc("NetUserDel").Call(0, uintptr(unsafe.Pointer(publicName))) // #nosec G103 -- deletes only the newly created name after current SID equality; never a wildcard or pre-existing account (CWE-242)
		if result != 0 {
			t.Error("owned rotation user cleanup failed", result)
		}
	})
	sid, _, _, err = windows.LookupSID("", name)
	if err != nil || !localSID(machine.SID, sid.String()) {
		t.Fatal("owned fixture is not the local SAM", err)
	}
	builtin, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		t.Fatal(err)
	}
	alias, _, _, err := builtin.LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	group, err = windows.UTF16PtrFromString(alias)
	if err != nil {
		t.Fatal(err)
	}
	member := struct{ SID *windows.SID }{sid}
	code, _, _ = netapi.NewProc("NetLocalGroupAddMembers").Call(0, uintptr(unsafe.Pointer(group)), 0, uintptr(unsafe.Pointer(&member)), 1) // #nosec G103 -- localized built-in alias, single exact owned local SID, no domain account or unrelated membership (CWE-242)
	if code != 0 {
		t.Fatal("owned rotation administrator grant failed", code)
	}
	added = true
	account, err := (nativeDriver{}).User(ctx, sid.String())
	if err != nil {
		t.Fatal(err)
	}
	return RotationBinding{Machine: machine, Account: account}, password
}
func TestNativeWindowsLocalAdministratorRotationA268(t *testing.T) {
	if os.Getenv("TRSTCTL_A268_WINDOWS_ROTATION") != "1" {
		t.Skip("owned native Windows password rotation fixture only")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	inventory, err := New().Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, oldFirst := ownedRotationAccount(t, ctx, inventory.Machine, "a")
	second, oldSecond := ownedRotationAccount(t, ctx, inventory.Machine, "b")
	nextFirst, err := crypto.RandomAccountPassword(32)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(nextFirst)
	nextSecond, err := crypto.RandomAccountPassword(32)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(nextSecond)
	if crypto.ConstantTimeEqual(nextFirst, nextSecond) {
		t.Fatal("distinct native targets reused one generated password")
	}
	for _, item := range []struct {
		binding RotationBinding
		old     *secret.Buffer
		next    []byte
	}{{first, oldFirst, nextFirst}, {second, oldSecond, nextSecond}} {
		native := nativeRotationDriver{}
		if sid, err := native.Authenticate(ctx, item.binding, item.old.Bytes()); err != nil || sid != item.binding.Account.SID {
			t.Fatal("owned predecessor did not authenticate before native rotation", err)
		}
		fence := &rotationFence{}
		proof, err := NewRotator().Rotate(ctx, item.binding, uuid.NewString(), item.old.Bytes(), item.next, fence)
		if err != nil || !proof.NewAuthenticated || !proof.OldRefused || fence.completes != 1 {
			t.Fatal("native rotation did not prove exact new SID and old refusal", err)
		}
		if sid, err := native.Authenticate(ctx, item.binding, item.next); err != nil || sid != item.binding.Account.SID {
			t.Fatal("native successor stopped authenticating after old-password refusal", err)
		}
	}
	t.Log("A268_WINDOWS_LOCAL_ROTATION_OK: two owned local SAM account contexts, distinct prepared passwords, exact network-logon token SIDs and predecessor refusal; no account/lockout policy relaxation. Native API fixture only: enrolled-host durable journal and fleet orchestration remain separate proofs.")
}
