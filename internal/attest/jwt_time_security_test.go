// SPDX-License-Identifier: MPL-2.0

package attest_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/attest/gcpmeta"
	"trstctl.com/trstctl/internal/attest/githuboidc"
	"trstctl.com/trstctl/internal/attest/k8ssat"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// The installed g104 broker accepted a signed Kubernetes proof whose nbf was
// one hour in the future. All JWT-backed attesters must enforce the same clock
// rules; a correct signature does not make a proof usable before its start time.
func TestJWTAttesterTimeWindows(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	jwk, err := crypto.PublicJWK(signer.Public(), "clock-proof")
	if err != nil {
		t.Fatal(err)
	}
	jwks := crypto.JWKS{Keys: []crypto.JWK{jwk}}
	now := time.Unix(1_900_000_000, 0).UTC()
	clock := func() time.Time { return now }
	const issuer = "https://issuer.qa.local"
	providers := []attest.Attestor{
		&k8ssat.Attestor{JWKS: jwks, Issuer: issuer, Audience: "trstctl", Now: clock},
		&githuboidc.Attestor{JWKS: jwks, Issuer: issuer, Audience: "trstctl", Now: clock},
		&gcpmeta.Attestor{JWKS: jwks, Issuer: issuer, Audience: "trstctl", Now: clock},
	}
	cases := []struct {
		name      string
		edit      func(map[string]any)
		wantError bool
	}{
		{"within window", func(c map[string]any) {}, false},
		{"exact start", func(c map[string]any) { c["nbf"] = now.Unix() }, false},
		{"one second before expiry", func(c map[string]any) { c["exp"] = now.Unix() + 1 }, false},
		{"optional start and issue times absent", func(c map[string]any) { delete(c, "nbf"); delete(c, "iat") }, false},
		{"future start", func(c map[string]any) { c["nbf"] = now.Unix() + 3600 }, true},
		{"one second before start", func(c map[string]any) { c["nbf"] = now.Unix() + 1 }, true},
		{"future issued at", func(c map[string]any) { c["iat"] = now.Unix() + 1 }, true},
		{"exact expiry", func(c map[string]any) { c["exp"] = now.Unix() }, true},
		{"expired", func(c map[string]any) { c["exp"] = now.Unix() - 1 }, true},
		{"expiry missing", func(c map[string]any) { delete(c, "exp") }, true},
		{"expiry wrong case", func(c map[string]any) { c["eXp"] = c["exp"]; delete(c, "exp") }, true},
		{"expiry null", func(c map[string]any) { c["exp"] = nil }, true},
		{"expiry zero", func(c map[string]any) { c["exp"] = int64(0) }, true},
		{"expiry wrong type", func(c map[string]any) { c["exp"] = "later" }, true},
		{"start wrong type", func(c map[string]any) { c["nbf"] = "later" }, true},
		{"start null", func(c map[string]any) { c["nbf"] = nil }, true},
		{"issued at wrong type", func(c map[string]any) { c["iat"] = "yesterday" }, true},
		{"issued at null", func(c map[string]any) { c["iat"] = nil }, true},
	}
	for _, provider := range providers {
		t.Run(provider.Method(), func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					claims := map[string]any{
						"iss": issuer, "aud": "trstctl", "sub": "system:serviceaccount:qa:clock-reader",
						"exp": now.Unix() + 7200, "nbf": now.Unix() - 60, "iat": now.Unix() - 60,
						"repository": "qa/clock-proof", "repository_owner": "qa",
						"kubernetes.io": map[string]any{"namespace": "qa", "serviceaccount": map[string]any{"name": "clock-reader"}},
						"google":        map[string]any{"compute_engine": map[string]any{"instance_id": "qa-instance", "project_id": "qa-project"}},
					}
					tc.edit(claims)
					token, err := crypto.SignJWT(signer, "clock-proof", claims)
					if err != nil {
						t.Fatal(err)
					}
					payload := []byte(token)
					defer secret.Wipe(payload)
					result, err := provider.Attest(context.Background(), payload)
					if (err != nil) != tc.wantError {
						t.Fatalf("verification error = %v, want rejection = %v", err, tc.wantError)
					}
					if !tc.wantError && result.Subject == "" {
						t.Fatal("valid proof returned no verified subject")
					}
				})
			}
		})
	}
}

// The oracle independently checks every accepted window, including malformed
// optional values. Signature verification is covered by the signed matrix above.
func FuzzJWTTimeWindow(f *testing.F) {
	for _, seed := range []string{
		`{"exp":1900000060,"nbf":1900000000,"iat":1899999999}`,
		`{"exp":1900000060,"nbf":1900000001}`,
		`{"exp":1900000000}`, `{"exp":null}`, `{"exp":0}`,
		`{"exp":1900000060,"nbf":null}`, `{"exp":9223372036854775808}`,
		`{"exp":1900000060,"iat":"later"}`, `{}`, `null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		const now = int64(1_900_000_000)
		if attest.ValidateJWTTimeWindow(raw, time.Unix(now, 0)) != nil {
			return
		}
		var claims map[string]json.RawMessage
		if json.Unmarshal(raw, &claims) != nil {
			t.Fatal("accepted malformed JSON")
		}
		for _, name := range []string{"exp", "nbf", "iat"} {
			value, present := claims[name]
			if !present {
				if name == "exp" {
					t.Fatal("accepted a proof without expiry")
				}
				continue
			}
			var seconds *int64
			if json.Unmarshal(value, &seconds) != nil || seconds == nil {
				t.Fatal("accepted a noninteger time")
			}
			if (name == "exp" && *seconds <= now) || (name != "exp" && *seconds > now) {
				t.Fatal("accepted a proof outside its time window")
			}
		}
	})
}
