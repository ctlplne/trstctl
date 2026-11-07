// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const ownedMachineSID = "S-1-5-21-10-20-30"

type inventoryFixture struct {
	machine Machine
	after   *Machine
	members []Member
	users   map[string]Account
	calls   []string
	reads   int
	failure error
}

func (f *inventoryFixture) Machine(context.Context) (Machine, error) {
	f.reads++
	if f.reads > 1 && f.after != nil {
		return *f.after, nil
	}
	return f.machine, nil
}
func (f *inventoryFixture) Administrators(ctx context.Context, accept func(Member) error) error {
	if f.failure != nil {
		return f.failure
	}
	for _, member := range f.members {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := accept(member); err != nil {
			return err
		}
	}
	return nil
}
func (f *inventoryFixture) User(_ context.Context, sid string) (Account, error) {
	f.calls = append(f.calls, sid)
	value, ok := f.users[sid]
	if !ok {
		return Account{}, errors.New("owned native member unresolved")
	}
	return value, nil
}
func ownedInventoryFixture() *inventoryFixture {
	sid := ownedMachineSID + "-500"
	return &inventoryFixture{machine: Machine{Name: "OWNED-MEMBER", SID: ownedMachineSID, Role: 3}, members: []Member{{SID: sid, Use: 1}, {SID: "S-1-5-21-99-98-97-1100", Use: 1}, {SID: "S-1-5-32-545", Use: 4}}, users: map[string]Account{sid: {Name: "Administrator", SID: sid, Enabled: true, PasswordRequired: true}}}
}
func TestNativeLocalInventoryKeepsExactSAMScopeAndMachineIdentityA268(t *testing.T) {
	fixture := ownedInventoryFixture()
	result, err := (Adapter{driver: fixture}).Inventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.Machine != fixture.machine || len(result.Accounts) != 1 || result.Accounts[0] != fixture.users[ownedMachineSID+"-500"] || result.ExternalMembers != 1 || result.GroupMembers != 1 {
		t.Fatalf("native local scope changed: %+v", result)
	}
	if !reflect.DeepEqual(fixture.calls, []string{ownedMachineSID + "-500"}) || fixture.reads != 2 {
		t.Fatal("foreign principal queried or final machine check omitted", fixture.calls, fixture.reads)
	}
}
func TestNativeLocalInventoryRefusesIncompleteOrChangedAuthorityA268(t *testing.T) {
	for _, kind := range []string{"domain controller", "unknown role", "duplicate SID", "unresolved local", "changed SID", "changed machine", "invalid native name", "reader failure", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			fixture := ownedInventoryFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch kind {
			case "domain controller":
				fixture.machine.Role = 4
			case "unknown role":
				fixture.machine.Role = 7
			case "duplicate SID":
				fixture.members = append(fixture.members, fixture.members[0])
			case "unresolved local":
				fixture.users = map[string]Account{}
			case "changed SID":
				value := fixture.users[ownedMachineSID+"-500"]
				value.SID = ownedMachineSID + "-501"
				fixture.users[ownedMachineSID+"-500"] = value
			case "changed machine":
				after := fixture.machine
				after.SID = "S-1-5-21-1-2-3"
				fixture.after = &after
			case "invalid native name":
				value := fixture.users[ownedMachineSID+"-500"]
				value.Name = "foreign\\Administrator"
				fixture.users[ownedMachineSID+"-500"] = value
			case "reader failure":
				fixture.failure = errors.New("owned native read failed")
			case "cancelled":
				cancel()
			}
			result, err := (Adapter{driver: fixture}).Inventory(ctx)
			if err == nil || len(result.Accounts) != 0 {
				t.Fatalf("partial or changed scope reported complete: %+v %v", result, err)
			}
			if (kind == "domain controller" || kind == "unknown role") && len(fixture.calls) != 0 {
				t.Fatal("nonlocal SAM was queried")
			}
		})
	}
}
func TestNativeWindowsNamesArePublicMetadataNotSSHArgumentsA268(t *testing.T) {
	for _, name := range []string{"Administrator", "Ops Admin", "John'sOps", strings.Repeat("名", 20)} {
		if !validName(name) {
			t.Fatal("valid native name refused", name)
		}
	}
	for _, name := range []string{"", "a\x00b", "domain\\user", "trailing.", strings.Repeat("名", 21), "a/b", "a\nb"} {
		if validName(name) {
			t.Fatal("invalid native name accepted", name)
		}
	}
}

func FuzzLocalSAMInventoryPublicFieldsA268(f *testing.F) {
	f.Add("Administrator", ownedMachineSID+"-500")
	f.Add("John'sOps", ownedMachineSID+"-500")
	f.Add("Admin", "S-1-5-21-99-98-97-500")
	f.Add("a\x00b", ownedMachineSID+"-500")
	f.Fuzz(func(t *testing.T, name, sid string) {
		fixture := ownedInventoryFixture()
		fixture.users[ownedMachineSID+"-500"] = Account{Name: name, SID: sid, Enabled: true, PasswordRequired: true}
		result, err := (Adapter{driver: fixture}).Inventory(t.Context())
		if err == nil && (len(result.Accounts) != 1 || result.Accounts[0].SID != ownedMachineSID+"-500" || result.Accounts[0].Name != name) {
			t.Fatal("native public input substituted account authority")
		}
	})
}

func TestNativeInventoryBoundNeverReturnsPartialAuthorityA268(t *testing.T) {
	fixture := ownedInventoryFixture()
	fixture.members = nil
	fixture.users = map[string]Account{}
	for n := 0; n < 8000; n++ {
		sid := ownedMachineSID + "-" + strconv.Itoa(1000+n)
		fixture.members = append(fixture.members, Member{SID: sid, Use: 1})
		fixture.users[sid] = Account{Name: "owned-admin-" + strconv.Itoa(n), SID: sid, Enabled: true, PasswordRequired: true}
	}
	result, err := (Adapter{driver: fixture}).Inventory(t.Context())
	if !errors.Is(err, ErrInventoryBound) || len(result.Accounts) != 0 {
		t.Fatal("native observation overflow became partial complete authority", err, len(result.Accounts))
	}
}
func TestNativeInventoryKeepsDisabledAndLockedAccountsVisibleA268(t *testing.T) {
	fixture := ownedInventoryFixture()
	account := fixture.users[ownedMachineSID+"-500"]
	account.Enabled = false
	account.Locked = true
	account.PasswordRequired = false
	fixture.users[account.SID] = account
	result, err := (Adapter{driver: fixture}).Inventory(t.Context())
	if err != nil || len(result.Accounts) != 1 || result.Accounts[0] != account {
		t.Fatal("inactive administrator metadata silently dropped", err)
	}
}

func TestNativeSIDOnlyEnumerationStillConfirmsTheLocalUserA268(t *testing.T) {
	fixture := ownedInventoryFixture()
	fixture.members[0].Use = 0
	result, err := (Adapter{driver: fixture}).Inventory(t.Context())
	if err != nil || len(result.Accounts) != 1 || !reflect.DeepEqual(fixture.calls, []string{ownedMachineSID + "-500"}) {
		t.Fatal("SID-only native member lacked exact local confirmation", err)
	}
	fixture = ownedInventoryFixture()
	fixture.members[0].Use = 0
	fixture.users = map[string]Account{}
	if _, err := (Adapter{driver: fixture}).Inventory(t.Context()); err == nil {
		t.Fatal("SID-only read guessed an unresolved local user's identity")
	}
}

func TestRemoteInventoryValidationRefusesDuplicateForeignOrUnboundedRowsA268(t *testing.T) {
	base := Inventory{Machine: Machine{Name: "OWNED", SID: "S-1-5-21-1-2-3", Role: 3}, Accounts: []Account{{Name: "OwnedAdmin", SID: "S-1-5-21-1-2-3-1001"}}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Inventory){
		func(v *Inventory) { v.Accounts = append(v.Accounts, v.Accounts[0]) },
		func(v *Inventory) {
			v.Accounts = append(v.Accounts, Account{Name: "ownedadmin", SID: "S-1-5-21-1-2-3-1002"})
		},
		func(v *Inventory) { v.Accounts[0].SID = "S-1-5-21-4-5-6-1001" },
		func(v *Inventory) { v.Machine.Role = 4 },
		func(v *Inventory) { v.Machine.Name = "host\n" },
		func(v *Inventory) { v.ExternalMembers = -1 },
		func(v *Inventory) { v.GroupMembers = MaxInventoryBytes },
	} {
		value := base
		value.Accounts = append([]Account{}, base.Accounts...)
		mutate(&value)
		if value.Validate() == nil {
			t.Fatal("invalid remote native inventory accepted")
		}
	}
}
