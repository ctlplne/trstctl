// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"trstctl.com/trstctl/internal/crypto/infratest"
)

// CR-009: one unrelated failed logon must not keep a revealed password alive
// by preventing an administrator reset. A proof bind still respects the DC's
// lockout threshold and does not send a password one attempt from lockout.
func TestCR009AdministrativeResetAndProofUseSeparateLockoutRules(t *testing.T) {
	entry := ldap.NewEntry(a258l1Account, map[string][]string{
		"sAMAccountName":                     {"svc-desktop"},
		"userAccountControl":                 {"512"},
		"msDS-User-Account-Control-Computed": {"0"},
		"badPwdCount":                        {"1"},
		"pwdLastSet":                         {"134070000000000000"},
		"accountExpires":                     {"9223372036854775807"},
	})
	if _, err := validateADAccountState(entry, false, time.Now()); err != nil {
		t.Fatalf("administrative reset refused after an unrelated failed logon: %v", err)
	}
	for _, flags := range []struct{ uac, computed string }{{"514", "0"}, {"512", "16"}} {
		unsafe := ldap.NewEntry(a258l1Account, map[string][]string{
			"sAMAccountName":                     {"svc-desktop"},
			"userAccountControl":                 {flags.uac},
			"msDS-User-Account-Control-Computed": {flags.computed},
			"badPwdCount":                        {"1"},
			"pwdLastSet":                         {"134070000000000000"},
			"accountExpires":                     {"9223372036854775807"},
		})
		if _, err := validateADAccountState(unsafe, false, time.Now()); err == nil {
			t.Fatalf("disabled or locked administrative target was accepted: %+v", flags)
		}
	}
	if err := (adSignInState{uac: 512, bad: ^uint64(0), pwdLastSet: 1, threshold: 5}).refusal(time.Now()); err == nil {
		t.Fatal("counter overflow allowed a proof bind into a lockout")
	}
	adminPassword := []byte("Tr5!admin-owned-cr009")
	password := []byte("Tr5!rotated-owned-cr009")
	d, err := infratest.StartAD(a258l1Domain, 5, a258l1Admin, adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	d.AddAccount(a258l1Account, "svc-desktop", password)
	backend := a258l1Backend(t, d, adminPassword)
	credential := a258l1Credential(t, a258l1Account, password)
	d.SetBadPwdCount(a258l1Account, 1)
	if err := backend.VerifyCredential(t.Context(), credential); err != nil {
		t.Fatalf("just-set password refused below the lockout margin: %v", err)
	}
	if got := d.SignIns(a258l1Account); got != 1 || d.Locked(a258l1Account) {
		t.Fatalf("safe proof bind count=%d locked=%v", got, d.Locked(a258l1Account))
	}
	d.SetBadPwdCount(a258l1Account, 4)
	if err := backend.VerifyCredential(t.Context(), credential); err == nil {
		t.Fatal("proof bind attempted one failure from lockout")
	}
	if got := d.SignIns(a258l1Account); got != 1 || d.Locked(a258l1Account) {
		t.Fatalf("unsafe proof reached DC: binds=%d locked=%v", got, d.Locked(a258l1Account))
	}
	// The shared sign-in path must retain the rotation proof's existing
	// account-name validation before it sends a target password.
	d.AddAccount(a258l1Account, "bad\nname", password)
	if err := backend.VerifyCredential(t.Context(), credential); err == nil || d.SignIns(a258l1Account) != 0 {
		t.Fatalf("malformed AD account name reached a target bind: err=%v binds=%d", err, d.SignIns(a258l1Account))
	}
}
