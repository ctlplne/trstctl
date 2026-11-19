// SPDX-License-Identifier: BUSL-1.1

package credref

import (
	"errors"
	"strings"
	"testing"
)

func TestStoredReferenceReturnsExactlyOneIdentity(t *testing.T) {
	for _, tc := range []struct {
		raw, name string
		version   int
	}{
		{"secret://team/application/token", "team/application/token", 0},
		{" secret://team/application/token ", "team/application/token", 0},
		{"secret://team/edge%20token?version=7", "team/edge token", 7},
		{"secret://team/application/token?version=2147483647", "team/application/token", 2147483647},
		{"secret://tenant%20group/prod/account%3Fversion=2", "tenant group/prod/account?version=2", 0},
		{"secret://tenant%40app/prod/token", "tenant@app/prod/token", 0},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := Parse(tc.raw)
			if err != nil || got.Name != tc.name || (tc.version == 0 && got.Version != nil) ||
				(tc.version != 0 && (got.Version == nil || *got.Version != tc.version)) {
				t.Fatalf("parse returned name=%q version=%v error=%v", got.Name, got.Version, err)
			}
		})
	}
}

func TestRejectedLegacyNameCanOnlyBeUsedForDenial(t *testing.T) {
	for _, raw := range []string{
		"secret:///team/application/token/",
		"secret://team/application%2Ftoken",
		"secret://team/application/%74oken",
		"secret://team/application/token?version=01",
	} {
		ref, err := Parse(raw)
		if ref != (Stored{}) || !errors.Is(err, ErrStoredFormat) || NameForDenial(err) != "team/application/token" {
			t.Errorf("legacy spelling %q did not retain only its denial scope", raw)
		}
	}
}

func TestStoredReferenceRejectsAChangedLegacyURLIdentity(t *testing.T) {
	for _, raw := range []string{
		"secret://fixture%2520group/team/token",
		"secret://%C2%A0fixture/team/token",
	} {
		if ref, err := Parse(raw); ref != (Stored{}) || !errors.Is(err, ErrStoredFormat) {
			t.Error("a retained URL spelling can now identify a different secret")
		}
	}
}

func FuzzParseStoredSecretReference(f *testing.F) {
	f.Add("secret://fixture/team/token")
	f.Add("secret://fixture/team/token?version=42")
	f.Add("secret://fixture/team%2Ftoken")
	f.Add("Secret://fixture/team/token")
	f.Add("secret://fixture/team/token?version=1&version=2")
	f.Fuzz(func(t *testing.T, raw string) {
		ref, err := Parse(raw)
		if err != nil {
			if ref != (Stored{}) || !errors.Is(err, ErrStoredFormat) {
				t.Fatal("a rejected reference carried a usable stored identity")
			}
			return
		}
		if !IsStored(raw) || !strings.HasPrefix(strings.TrimSpace(raw), storedPrefix) || ref.Name == "" ||
			(ref.Version != nil && *ref.Version <= 0) {
			t.Fatal("an accepted reference had an invalid scheme, name or version")
		}
	})
}
