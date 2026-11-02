// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"encoding/json"
	"testing"
	"time"
)

// RFC 6238's SHA1 seed "12345678901234567890" in base32, as an authenticator
// app would show it.
const rfc6238SeedBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // #nosec G101 -- the RFC 6238 test-vector seed, not a credential (CWE-798)

// A239: a lease is the seed's code for the current step, matching RFC 6238,
// with the end of the step as its expiry bound; revocation can't withdraw it.
func TestTOTPBackendIssuesTheCurrentCodeWithItsExpiryA239(t *testing.T) {
	at := time.Unix(59, 0)
	for _, v := range []struct {
		digits int
		seed   string
		want   string
	}{
		{6, rfc6238SeedBase32, "287082"},
		{8, "gezd gnbv gy3t qojq gezd gnbv gy3t qojq", "94287082"},
	} {
		b, err := NewTOTPBackend(TOTPConfig{SeedBase32: []byte(v.seed), Digits: v.digits, Now: func() time.Time { return at }})
		if err != nil {
			t.Fatal(err)
		}
		ref, raw, err := b.CreateCredential(t.Context(), GenerateRequest{Role: "login", LeaseID: "lease-1"})
		if err != nil {
			t.Fatal(err)
		}
		var credential struct {
			Code          string    `json:"code"`
			ValidUntil    time.Time `json:"valid_until"`
			PeriodSeconds int64     `json:"period_seconds"`
		}
		if err := json.Unmarshal(raw, &credential); err != nil || credential.Code != v.want ||
			!credential.ValidUntil.Equal(time.Unix(60, 0)) || credential.PeriodSeconds != 30 || ref != "totp-step-1" {
			t.Fatalf("ref %q credential %+v err %v", ref, credential, err)
		}
		if err := b.Revoke(t.Context(), ref); err != nil {
			t.Fatal(err)
		}
		b.Close()
	}
}

// A239: the provider refuses parameters a stock authenticator wouldn't use and
// seeds too short or not base32.
func TestTOTPBackendRefusesBadParametersA239(t *testing.T) {
	for name, cfg := range map[string]TOTPConfig{
		"45s period": {SeedBase32: []byte(rfc6238SeedBase32), Period: 45 * time.Second},
		"md5":        {SeedBase32: []byte(rfc6238SeedBase32), Algorithm: "MD5"},
		"9 digits":   {SeedBase32: []byte(rfc6238SeedBase32), Digits: 9},
		"short seed": {SeedBase32: []byte("GEZDGNBV")},
		"not base32": {SeedBase32: []byte("not base32 at all 189")},
		"empty seed": {},
	} {
		if _, err := NewTOTPBackend(cfg); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	b, err := NewTOTPBackend(TOTPConfig{SeedBase32: []byte(rfc6238SeedBase32), Period: time.Minute, Algorithm: "sha256"})
	if err != nil {
		t.Fatalf("a 60-second SHA256 configuration: %v", err)
	}
	defer b.Close()
	if _, _, err := b.CreateCredential(t.Context(), GenerateRequest{Role: "login", Static: true}); err == nil {
		t.Fatal("a static TOTP credential was issued")
	}
}
