// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// CR-821 and CR-819: the signed statement and sealing context must carry
// the exact same CA import policy, issuer identity and expiration.
func TestAuthenticatedKeyImportOfferBindsExactPolicy(t *testing.T) {
	identity, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Destroy)
	recipient, err := GenerateKeyImportKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(recipient.Destroy)
	const operation = "00000000-0000-4000-8000-000000082114"
	policy := CAKeyImportPolicy(
		"00000000-0000-4000-8000-000000082115", operation, identity.Public().DER,
	)
	now := time.Unix(1_800_000_000, 0).UTC()
	offer, err := SignKeyImportOffer(policy, recipient.Public(), now, identity)
	if err != nil {
		t.Fatal(err)
	}
	pin := SHA256Hex(identity.Public().DER)
	info, err := offer.Verify(pin, now)
	if err != nil {
		t.Fatal(err)
	}
	reconstructed, err := offer.HPKEInfo()
	if err != nil || !bytes.Equal(info, reconstructed) {
		t.Fatal("the verifier and HPKE reconstruction must use the same transcript")
	}
	for _, tc := range []struct {
		name   string
		change func(*AuthenticatedKeyImportOffer)
	}{
		{"different tenant", func(o *AuthenticatedKeyImportOffer) {
			o.TenantID = "00000000-0000-4000-8000-000000082116"
		}},
		{"different operation", func(o *AuthenticatedKeyImportOffer) {
			o.OperationID = "00000000-0000-4000-8000-000000082118"
			o.Handle = CAHierarchySignerHandle(o.OperationID)
		}},
		{"different recipient", func(o *AuthenticatedKeyImportOffer) {
			o.PublicKey = slices.Clone(o.PublicKey)
			o.PublicKey[len(o.PublicKey)-1] ^= 1
		}},
		{"different version", func(o *AuthenticatedKeyImportOffer) { o.Version++ }},
		{"legacy suite", func(o *AuthenticatedKeyImportOffer) { o.Suite = KeyImportSuite }},
		{"different expected key", func(o *AuthenticatedKeyImportOffer) {
			o.ExpectedPublicKey = slices.Clone(o.ExpectedPublicKey)
			o.ExpectedPublicKey[len(o.ExpectedPublicKey)-1] ^= 1
		}},
		{"different handle", func(o *AuthenticatedKeyImportOffer) { o.Handle += "a" }},
		{"different usage", func(o *AuthenticatedKeyImportOffer) { o.AllowedPurposes = []int32{2} }},
		{"different hashes", func(o *AuthenticatedKeyImportOffer) { o.AllowedHashes = []int32{1} }},
		{"different authorization", func(o *AuthenticatedKeyImportOffer) { o.RequireAuthorization = false }},
		{"shifted lifetime", func(o *AuthenticatedKeyImportOffer) { o.IssuedAt++; o.ExpiresAt++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := offer
			tc.change(&tampered)
			if _, err := tampered.Verify(pin, now); err == nil {
				t.Fatal("offer was accepted after altering its authenticated policy")
			}
		})
	}
	if _, err := offer.Verify(SHA256Hex([]byte("use a separately pinned fixture identity")), now); err == nil {
		t.Fatal("offer verified against a different independently supplied pin")
	}
	if _, err := offer.Verify(pin, time.Unix(offer.ExpiresAt, 0)); err == nil {
		t.Fatal("offer remained usable at the exclusive expiry boundary")
	}
	if _, err := offer.Verify(pin, now.Add(-keyImportOfferClockSkew-time.Second)); err == nil {
		t.Fatal("offer verified before the permitted clock skew")
	}
}

func FuzzAuthenticatedKeyImportOffer(f *testing.F) {
	// A deterministic test identity and recipient make the seed valid in
	// each Go fuzz worker, which initializes the fixture independently.
	private, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{0x37}, 32))
	if err != nil {
		f.Fatal(err)
		return
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		f.Fatal(err)
		return
	}
	identity, err := NewLockedSignerFromPKCS8(ECDSAP256, der)
	secret.Wipe(der)
	if err != nil {
		f.Fatal(err)
		return
	}
	f.Cleanup(identity.Destroy)
	recipient, err := NewKeyImportKey(bytes.Repeat([]byte{0x29}, KeyImportSeedSize))
	if err != nil {
		f.Fatal(err)
		return
	}
	f.Cleanup(recipient.Destroy)
	policy := CAKeyImportPolicy(
		"00000000-0000-4000-8000-000000082115",
		"00000000-0000-4000-8000-000000082114", identity.Public().DER,
	)
	now := time.Unix(1_800_000_000, 0).UTC()
	offer, err := SignKeyImportOffer(policy, recipient.Public(), now, identity)
	if err != nil {
		f.Fatal(err)
		return
	}
	original, err := json.Marshal(offer)
	if err != nil {
		f.Fatal(err)
		return
	}
	pin := SHA256Hex(identity.Public().DER)
	expected, err := offer.Verify(pin, now)
	if err != nil {
		f.Fatal(err)
		return
	}
	f.Add(original)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64<<10 {
			return
		}
		var parsed AuthenticatedKeyImportOffer
		if json.Unmarshal(input, &parsed) != nil {
			return
		}
		if got, err := parsed.Verify(pin, now); err == nil && !bytes.Equal(got, expected) {
			t.Fatal("a different sealing transcript accepted the fixture signature")
		}
	})
}
