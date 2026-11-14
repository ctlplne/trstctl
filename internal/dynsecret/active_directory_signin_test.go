// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/infratest"
	"trstctl.com/trstctl/internal/crypto/ldapbind"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	a258l1Domain  = "DC=corp,DC=test"
	a258l1Admin   = "CN=Rotator,CN=Users,DC=corp,DC=test"
	a258l1Account = "CN=svc-desktop,OU=Trstctl,DC=corp,DC=test"
	a258l1PSO     = "CN=Strict,CN=Password Settings Container,CN=System,DC=corp,DC=test"
)

func a258l1Backend(t *testing.T, d *infratest.AD, admin []byte) *LDAPBackend {
	t.Helper()
	cfg := LDAPConfig{DirectoryMode: "active_directory", Addr: d.Addr(), TLSServerName: infratest.ADServerName, TLSCAPEM: d.CAPEM(),
		BindDN: a258l1Admin, BindPassword: admin, UsersDN: "OU=Trstctl,DC=corp,DC=test",
		RoleGroups: map[string]string{"desktop/account": a258l1Account}}
	backend, err := NewLDAPBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Close)
	return backend
}

func a258l1Credential(t *testing.T, dn string, password []byte) []byte {
	t.Helper()
	raw, err := json.Marshal(struct { // #nosec G117 -- a test's own fixture credential (CWE-200)
		BindDN   string           `json:"bind_dn"`
		Password secret.JSONBytes `json:"password"`
	}{dn, password})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A258-L1 Done-when (unit, Active Directory stand-in): a vaulted AD account's
// check reads badPwdCount and the lockout threshold that applies to the
// account before it signs in, and never signs in when a refused password
// would lock it. With a domain threshold of 3 a wrong vaulted password is
// tried while the account is at 0 and 1 failed sign-ins and reads rejected;
// at 2 the check — with the wrong password or the right one, however often —
// reads lockout_risk and sends nothing, and the account never locks. A
// password settings object's threshold of 2 wins over the domain's; one that
// cannot be read sends nothing; a domain threshold of 0 never locks. Locked,
// disabled, expired and must-change accounts are classified from their state
// without a sign-in.
func TestADAccountSignInCheckNeverBindsIntoALockoutA258L1(t *testing.T) {
	ctx := t.Context()
	adminPassword := []byte("Tr5!admin-" + "owned-fixture")
	right := []byte("Tr5!vaulted-" + "owned-fixture")
	wrong := []byte("Tr5!changed-" + "elsewhere-fixture")
	d, err := infratest.StartAD(a258l1Domain, 3, a258l1Admin, adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	d.AddAccount(a258l1Account, "svc-desktop", right)
	backend := a258l1Backend(t, d, adminPassword)
	check := func(password []byte) string {
		t.Helper()
		return SignInStatusOf(backend.CheckADAccountSignIn(ctx, a258l1Credential(t, a258l1Account, password)))
	}
	expect := func(step, got, want string, signIns, bad int) {
		t.Helper()
		if got != want || d.SignIns(a258l1Account) != signIns || d.BadPwdCount(a258l1Account) != bad || d.Locked(a258l1Account) {
			t.Fatalf("%s: read %s with %d sign-ins, badPwdCount %d, locked %v; want %s, %d, %d, not locked",
				step, got, d.SignIns(a258l1Account), d.BadPwdCount(a258l1Account), d.Locked(a258l1Account), want, signIns, bad)
		}
	}

	expect("the vaulted password", check(right), SignInHealthy, 1, 0)
	expect("a changed password at 0", check(wrong), SignInRejected, 2, 1)
	expect("a changed password at 1", check(wrong), SignInRejected, 3, 2)
	for i := 0; i < 10; i++ {
		expect("a changed password one short of lockout", check(wrong), SignInLockoutRisk, 3, 2)
		expect("the right password one short of lockout", check(right), SignInLockoutRisk, 3, 2)
	}
	if SignInJudged(SignInLockoutRisk) {
		t.Fatal("lockout_risk is not a judgment of the credential: the next scheduled check reads the count again")
	}

	// The count clears (the observation window ends): the right password signs in.
	d.SetBadPwdCount(a258l1Account, 0)
	expect("the right password after the count cleared", check(right), SignInHealthy, 4, 0)

	// The password settings object's threshold applies, not the domain's.
	d.ApplyPSO(a258l1Account, a258l1PSO, 2)
	d.SetBadPwdCount(a258l1Account, 1)
	expect("one short of the settings object's threshold", check(wrong), SignInLockoutRisk, 4, 1)
	d.HidePSOs()
	expect("settings that cannot be read", check(right), SignInError, 4, 1)

	// A domain threshold of 0 never locks: the check signs in at any count.
	other, err := infratest.StartAD(a258l1Domain, 0, a258l1Admin, adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	other.AddAccount(a258l1Account, "svc-desktop", right)
	other.SetBadPwdCount(a258l1Account, 50)
	if got := SignInStatusOf(a258l1Backend(t, other, adminPassword).CheckADAccountSignIn(ctx, a258l1Credential(t, a258l1Account, right))); got != SignInHealthy || other.SignIns(a258l1Account) != 1 {
		t.Fatalf("no lockout policy: read %s with %d sign-ins", got, other.SignIns(a258l1Account))
	}

	// State alone classifies an account that cannot sign in.
	for _, tc := range []struct {
		name  string
		set   func(*infratest.AD)
		state string
	}{
		{"locked", func(ad *infratest.AD) { ad.Lock(a258l1Account) }, SignInLocked},
		{"disabled", func(ad *infratest.AD) { ad.Disable(a258l1Account) }, SignInRejected},
		{"expired", func(ad *infratest.AD) { ad.Expire(a258l1Account) }, SignInExpired},
		{"must change", func(ad *infratest.AD) { ad.MustChange(a258l1Account) }, SignInExpired},
	} {
		ad, err := infratest.StartAD(a258l1Domain, 3, a258l1Admin, adminPassword)
		if err != nil {
			t.Fatal(err)
		}
		ad.AddAccount(a258l1Account, "svc-desktop", right)
		tc.set(ad)
		got := SignInStatusOf(a258l1Backend(t, ad, adminPassword).CheckADAccountSignIn(ctx, a258l1Credential(t, a258l1Account, right)))
		if got != tc.state || ad.SignIns(a258l1Account) != 0 {
			t.Fatalf("%s: read %s with %d sign-ins; want %s and none", tc.name, got, ad.SignIns(a258l1Account), tc.state)
		}
		ad.Close()
	}

	// An account outside the provider's bindings is never tried.
	if err := backend.CheckADAccountSignIn(ctx, a258l1Credential(t, "CN=someone-else,OU=Trstctl,DC=corp,DC=test", right)); err == nil || SignInStatusOf(err) != SignInError {
		t.Fatalf("an unbound account: %v", err)
	}
	// A directory that cannot be reached is unreachable, before any password.
	d.Close()
	if got := check(right); got != SignInUnreachable {
		t.Fatalf("a closed directory read %s", got)
	}
}

// A258-L1: a refused sign-in's class follows Active Directory's sub-status.
func TestADSignInRefusalClassesA258L1(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&ldapbind.RefusalError{Result: 49, ADData: 0x52e}, SignInRejected},
		{&ldapbind.RefusalError{Result: 49, ADData: 0x525}, SignInRejected},
		{&ldapbind.RefusalError{Result: 49, ADData: 0x533}, SignInRejected},
		{&ldapbind.RefusalError{Result: 49}, SignInRejected},
		{&ldapbind.RefusalError{Result: 49, ADData: 0x775}, SignInLocked},
		{&ldapbind.RefusalError{Result: 49, ADData: 0x532}, SignInExpired},
		{&ldapbind.RefusalError{Result: 49, ADData: 0x773}, SignInExpired},
		{&ldapbind.RefusalError{Result: 49, ADData: 0x701}, SignInExpired},
		{&ldapbind.RefusalError{Result: 49, ADData: 0x530}, SignInError},
		{&ldapbind.RefusalError{Result: 49, ADData: 0x531}, SignInError},
		{&ldapbind.RefusalError{Result: 53}, SignInError},
		{ldapbind.ErrConnect, SignInUnreachable},
		{errors.New("LDAP encrypted bind response failed"), SignInError},
	} {
		if got := SignInStatusOf(classifyADSignIn(tc.err)); got != tc.want {
			t.Fatalf("%v: %s, want %s", tc.err, got, tc.want)
		}
	}
	if adExpired(0, time.Now()) || adExpired(9223372036854775807, time.Now()) || !adExpired(132000000000000000, time.Now()) {
		t.Fatal("accountExpires: 0 and the largest int64 never expire; a past FILETIME has")
	}
}
