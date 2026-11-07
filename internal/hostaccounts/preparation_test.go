// SPDX-License-Identifier: BUSL-1.1
package hostaccounts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"testing/quick"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
)

func privatePreparationFixture() (RotationPreparation, error) {
	i, e := NewRotationIntent(RotationIntent{RotationID: "11111111-1111-4111-8111-111111111111", AccountID: "22222222-2222-4222-8222-222222222222", TenantID: "33333333-3333-4333-8333-333333333333", AgentID: "44444444-4444-4444-8444-444444444444", InventoryRunID: "55555555-5555-4555-8555-555555555555", Native: winaccounts.RotationBinding{Machine: winaccounts.Machine{Name: "owned", SID: "S-1-5-21-1-2-3", Role: 3}, Account: winaccounts.Account{Name: "本地 Admin", SID: "S-1-5-21-1-2-3-1001", Enabled: true, PasswordRequired: true}}})
	return RotationPreparation{Intent: i, ProviderBinding: strings.Repeat("a", 64), Role: "host/admin", Credential: LocalCredential{Host: "owned", Username: "本地 Admin", Password: secret.JSONBytes("public-owned-test-fixture-password")}}, e
}
func TestSealedNativePreparationRetainsExactByteCredentialA268(t *testing.T) {
	p, e := privatePreparationFixture()
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(p.Credential.Password)
	raw, e := MarshalRotationPreparation(p)
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(raw)
	got, e := DecodeRotationPreparation(raw)
	if e != nil || got.Intent != p.Intent || got.Role != p.Role {
		t.Fatal("sealed generation changed", e)
	}
	secret.Wipe(got.Credential.Password)
	p.Credential.Username = "other"
	raw, e = json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(raw)
	if got, e = DecodeRotationPreparation(raw); e == nil {
		secret.Wipe(got.Credential.Password)
		t.Fatal("another SAM account accepted")
	}
}
func FuzzNativeLocalAccountPrivatePreparationA268(f *testing.F) {
	p, e := privatePreparationFixture()
	if e != nil {
		f.Fatal(e)
		return
	}
	defer secret.Wipe(p.Credential.Password)
	raw, e := MarshalRotationPreparation(p)
	if e != nil {
		f.Fatal(e)
		return
	}
	defer secret.Wipe(raw)
	f.Add(raw)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, e := DecodeRotationPreparation(raw)
		defer secret.Wipe(p.Credential.Password)
		if e == nil && p.Intent.Validate() != nil {
			t.Fatal("invalid native intent survived private decoder")
		}
	})
}

func TestPrivateLocalCredentialRejectsDuplicatePasswordA268(t *testing.T) {
	p, e := privatePreparationFixture()
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(p.Credential.Password)
	raw := []byte(`{"host":"owned","username":"本地 Admin","password":"first","password":"second"}`)
	defer secret.Wipe(raw)
	got, e := DecodeLocalCredential(raw, p.Intent)
	defer secret.Wipe(got.Password)
	if e == nil {
		t.Fatal("duplicate password field was accepted")
	}
}

func TestNativePreparedCredentialByteRoundTripPropertyA268(t *testing.T) {
	fixture, e := privatePreparationFixture()
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(fixture.Credential.Password)
	property := func(input []byte) bool {
		candidate := fixture
		candidate.Credential.Password = make(secret.JSONBytes, len(fixture.Credential.Password)+len(input))
		copy(candidate.Credential.Password, fixture.Credential.Password)
		alphabet := []byte("aA1\"\\\n\t&<>")
		for pos, value := range input {
			candidate.Credential.Password[len(fixture.Credential.Password)+pos] = alphabet[int(value)%len(alphabet)]
		}
		defer secret.Wipe(candidate.Credential.Password)
		raw, e := MarshalRotationPreparation(candidate)
		if e != nil {
			return false
		}
		defer secret.Wipe(raw)
		before := append([]byte(nil), raw...)
		defer secret.Wipe(before)
		got, e := DecodeRotationPreparation(raw)
		defer secret.Wipe(got.Credential.Password)
		return e == nil && bytes.Equal(raw, before) && bytes.Equal(got.Credential.Password, candidate.Credential.Password) && got.Intent == candidate.Intent
	}
	if e := quick.Check(property, &quick.Config{MaxCount: 500}); e != nil {
		t.Fatal("private encoding/custody round-trip property failed")
	}
}
