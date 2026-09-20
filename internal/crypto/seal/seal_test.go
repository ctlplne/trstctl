// SPDX-License-Identifier: BUSL-1.1

package seal_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
)

func newKEK(t *testing.T) *seal.LocalKEK {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	k, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	t.Cleanup(k.Destroy)
	return k
}

// TestSealOpenRoundTrip: a sealed credential opens back to the original under the
// same KEK.
func TestSealOpenRoundTrip(t *testing.T) {
	kek := newKEK(t)
	plaintext := []byte("super-secret-ca-api-key-0123456789")

	sealed, err := seal.Seal(kek, plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := seal.Open(kek, sealed, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

// TestSealedIsNotPlaintext: the at-rest blob is ciphertext — the plaintext must
// not appear in it (this is the "encrypted at rest" guarantee).
func TestSealedIsNotPlaintext(t *testing.T) {
	kek := newKEK(t)
	plaintext := []byte("P@ssw0rd-do-not-store-in-the-clear")
	sealed, err := seal.Seal(kek, plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("sealed blob contains the plaintext; it is not encrypted at rest")
	}
	// Sealing the same value twice yields different blobs (fresh DEK + nonces).
	sealed2, _ := seal.Seal(kek, plaintext, nil)
	if bytes.Equal(sealed, sealed2) {
		t.Error("two seals of the same plaintext are identical; nonce/DEK is not random")
	}
}

// TestOpenRejectsTamper: AEAD integrity — any bit flip in the sealed blob fails
// to open.
func TestOpenRejectsTamper(t *testing.T) {
	kek := newKEK(t)
	sealed, err := seal.Seal(kek, []byte("rotate-me"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := seal.Open(kek, tampered, nil); err == nil {
		t.Fatal("Open accepted a tampered blob; integrity not enforced")
	}
}

// TestOpenRejectsWrongKEK: a blob sealed under one KEK cannot be opened under
// another.
func TestOpenRejectsWrongKEK(t *testing.T) {
	k1 := newKEK(t)
	k2 := newKEK(t)
	sealed, err := seal.Seal(k1, []byte("client-secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := seal.Open(k2, sealed, nil); err == nil {
		t.Fatal("Open succeeded under the wrong KEK")
	}
}

// TestAADBinds: associated data binds the ciphertext to a context; opening with
// different AAD fails (prevents swapping a sealed credential into another row).
func TestAADBinds(t *testing.T) {
	kek := newKEK(t)
	sealed, err := seal.Seal(kek, []byte("token"), []byte("tenant-A/issuer-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := seal.Open(kek, sealed, []byte("tenant-B/issuer-1")); err == nil {
		t.Fatal("Open succeeded with mismatched AAD; binding not enforced")
	}
	if _, err := seal.Open(kek, sealed, []byte("tenant-A/issuer-1")); err != nil {
		t.Fatalf("Open with correct AAD failed: %v", err)
	}
}

// TestErrorDoesNotLeakPlaintext: a failed Open must not echo the plaintext (no
// secret in errors).
func TestErrorDoesNotLeakPlaintext(t *testing.T) {
	kek := newKEK(t)
	plaintext := []byte("leak-canary-7f3a")
	sealed, _ := seal.Seal(kek, plaintext, nil)
	sealed[len(sealed)-1] ^= 0xFF
	_, err := seal.Open(kek, sealed, nil)
	if err == nil {
		t.Fatal("expected an error opening a tampered blob")
	}
	if bytes.Contains([]byte(err.Error()), plaintext) {
		t.Errorf("error message leaks the plaintext: %v", err)
	}
}

// TestNewLocalKEKRejectsWrongSize: the local KEK must be a 256-bit key.
func TestNewLocalKEKRejectsWrongSize(t *testing.T) {
	if _, err := seal.NewLocalKEK(make([]byte, 16)); err == nil {
		t.Error("NewLocalKEK accepted a 16-byte key; want 32-byte (AES-256) requirement")
	}
}

// TestOpenDispatchesOnVersionByte is the SCHEMA-005 acceptance: Open reads the
// version byte and dispatches to that version's reader, rather than hard-rejecting
// anything that is not the single current version. Both the legacy v1 and
// domain-aware v2 layouts round-trip; an unknown version is rejected with
// ErrFormat because the reader never guesses a layout.
func TestOpenDispatchesOnVersionByte(t *testing.T) {
	kek := newKEK(t)
	plaintext := []byte("dispatch-me-by-version")
	v1, err := seal.Seal(kek, plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// The version byte sits immediately after the 4-byte magic "CSL1".
	const versionOffset = 4
	if v1[versionOffset] != 1 {
		t.Fatalf("expected v1 blob to carry version byte 1, got %d", v1[versionOffset])
	}
	v2, err := seal.SealDomain(kek, plaintext, nil, []byte("tenant:dispatch:generation:1"))
	if err != nil {
		t.Fatalf("SealDomain: %v", err)
	}
	if v2[versionOffset] != 2 {
		t.Fatalf("expected v2 blob to carry version byte 2, got %d", v2[versionOffset])
	}

	cases := []struct {
		name       string
		blob       []byte
		wantOpenOK bool
	}{
		{"v1 round-trips", v1, true},
		{"v2 round-trips", v2, true},
		{"unknown v0 rejected", withVersion(v1, 0), false},
		{"unknown v255 rejected", withVersion(v1, 255), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := seal.Open(kek, tc.blob, nil)
			if tc.wantOpenOK {
				if err != nil {
					t.Fatalf("Open failed: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("Open = %q, want %q", got, plaintext)
				}
				return
			}
			// Unknown version: must be rejected as a format error (fail closed), and
			// must NOT be silently decoded against the v1 layout.
			if err == nil {
				t.Fatal("Open accepted an unknown version; want ErrFormat")
			}
			if !errors.Is(err, seal.ErrFormat) {
				t.Fatalf("Open error = %v, want ErrFormat", err)
			}
		})
	}
}

func withVersion(sealed []byte, version byte) []byte {
	out := append([]byte(nil), sealed...)
	out[4] = version
	return out
}

// TestOpenRejectsTruncatedVersionedHeader: a blob too short to even carry the
// version byte is a format error, not a panic.
func TestOpenRejectsTruncatedVersionedHeader(t *testing.T) {
	kek := newKEK(t)
	if _, err := seal.Open(kek, []byte("CSL1"), nil); !errors.Is(err, seal.ErrFormat) {
		t.Fatalf("Open of a magic-only blob = %v, want ErrFormat", err)
	}
}

// TestTenantDomainSealRoundTrip proves the v2 container is self-describing and
// that callers must name the domain they expect. This lets a partially migrated
// tenant select one wrapper deterministically instead of trying the deployment
// KEK and silently falling back.
func TestTenantDomainSealRoundTrip(t *testing.T) {
	kek := newKEK(t)
	domain := []byte("tenant:2f1da31b-2142-45df-897f-f42fd573a9ef:generation:7")
	aad := []byte("tenant:2f1da31b-2142-45df-897f-f42fd573a9ef/secret:db")
	plaintext := []byte("tenant-controlled-secret")

	sealed, err := seal.SealDomain(kek, plaintext, aad, domain)
	if err != nil {
		t.Fatalf("SealDomain: %v", err)
	}
	gotDomain, err := seal.Domain(sealed)
	if err != nil {
		t.Fatalf("Domain: %v", err)
	}
	if !bytes.Equal(gotDomain, domain) {
		t.Fatalf("Domain = %q, want %q", gotDomain, domain)
	}
	got, err := seal.OpenDomain(kek, sealed, aad, domain)
	if err != nil {
		t.Fatalf("OpenDomain: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("OpenDomain = %q, want %q", got, plaintext)
	}

	gotDomain[0] ^= 0xff
	again, err := seal.Domain(sealed)
	if err != nil {
		t.Fatalf("Domain after caller mutation: %v", err)
	}
	if !bytes.Equal(again, domain) {
		t.Fatal("Domain returned a slice aliased to the stored blob")
	}
}

func TestTenantDomainSealRejectsWrongOrTamperedDomain(t *testing.T) {
	kek := newKEK(t)
	domain := []byte("tenant:a:generation:1")
	aad := []byte("tenant:a/secret:db")
	sealed, err := seal.SealDomain(kek, []byte("credential"), aad, domain)
	if err != nil {
		t.Fatalf("SealDomain: %v", err)
	}

	if _, err := seal.OpenDomain(kek, sealed, aad, []byte("tenant:b:generation:1")); !errors.Is(err, seal.ErrDomain) {
		t.Fatalf("OpenDomain wrong domain = %v, want ErrDomain", err)
	}

	tampered := append([]byte(nil), sealed...)
	const firstDomainByte = 4 + 1 + 2
	tampered[firstDomainByte] ^= 0x01
	if _, err := seal.OpenDomain(kek, tampered, aad, domain); !errors.Is(err, seal.ErrDomain) {
		t.Fatalf("OpenDomain tampered public domain = %v, want ErrDomain", err)
	}
}

func TestTenantDomainRewrapPreservesPayloadCiphertext(t *testing.T) {
	deploymentKEK := newKEK(t)
	tenantKEK := newKEK(t)
	tenantDomain := []byte("tenant:75d970a1-7083-402e-bbea-0ef93e455210:generation:1")
	aad := []byte("tenant:75d970a1-7083-402e-bbea-0ef93e455210/secret:db")
	plaintext := []byte("rewrap-without-plaintext-persistence")

	before, err := seal.Seal(deploymentKEK, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal legacy v1: %v", err)
	}
	legacyDomain, err := seal.Domain(before)
	if err != nil {
		t.Fatalf("Domain legacy v1: %v", err)
	}
	if legacyDomain != nil {
		t.Fatalf("legacy v1 Domain = %q, want nil", legacyDomain)
	}
	beforePayload, err := seal.PayloadCiphertext(before)
	if err != nil {
		t.Fatalf("PayloadCiphertext before: %v", err)
	}

	after, err := seal.RewrapDomain(deploymentKEK, tenantKEK, before, tenantDomain)
	if err != nil {
		t.Fatalf("RewrapDomain: %v", err)
	}
	afterPayload, err := seal.PayloadCiphertext(after)
	if err != nil {
		t.Fatalf("PayloadCiphertext after: %v", err)
	}
	if !bytes.Equal(afterPayload, beforePayload) {
		t.Fatal("RewrapDomain changed the nonce or payload ciphertext")
	}
	if _, err := seal.OpenDomain(deploymentKEK, after, aad, tenantDomain); err == nil {
		t.Fatal("rewrapped blob still opens with deployment KEK")
	}
	got, err := seal.OpenDomain(tenantKEK, after, aad, tenantDomain)
	if err != nil {
		t.Fatalf("OpenDomain with tenant KEK: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("OpenDomain = %q, want %q", got, plaintext)
	}
}

func TestTenantDomainRewrapZeroizesUnwrappedDEK(t *testing.T) {
	source := &capturingWrapper{}
	destination := &copyingWrapper{}
	domain := []byte("tenant:a:generation:1")
	sealed, err := seal.SealDomain(source, []byte("credential"), nil, domain)
	if err != nil {
		t.Fatalf("SealDomain: %v", err)
	}
	source.unwrapped = nil

	if _, err := seal.RewrapDomain(source, destination, sealed, []byte("tenant:a:generation:2")); err != nil {
		t.Fatalf("RewrapDomain: %v", err)
	}
	if len(source.unwrapped) == 0 {
		t.Fatal("test wrapper did not capture an unwrapped DEK")
	}
	if !bytes.Equal(source.unwrapped, make([]byte, len(source.unwrapped))) {
		t.Fatal("RewrapDomain did not zeroize the unwrapped DEK")
	}
}

func TestValidateDomainAuthenticatesWithoutOpeningPayload(t *testing.T) {
	kek := newKEK(t)
	otherKEK := newKEK(t)
	domain := []byte("tenant:a:generation:1")
	sealed, err := seal.SealDomain(kek, []byte("payload"), []byte("unknown-to-migrator-aad"), domain)
	if err != nil {
		t.Fatalf("SealDomain: %v", err)
	}
	if err := seal.ValidateDomain(kek, sealed, domain); err != nil {
		t.Fatalf("ValidateDomain: %v", err)
	}
	if err := seal.ValidateDomain(kek, sealed, []byte("tenant:b:generation:1")); !errors.Is(err, seal.ErrDomain) {
		t.Fatalf("ValidateDomain wrong label = %v, want ErrDomain", err)
	}
	if err := seal.ValidateDomain(otherKEK, sealed, domain); !errors.Is(err, seal.ErrDecrypt) {
		t.Fatalf("ValidateDomain wrong wrapper = %v, want ErrDecrypt", err)
	}
	if err := seal.ValidateDomain(kek, withVersion(sealed, 1), domain); !errors.Is(err, seal.ErrDomain) {
		t.Fatalf("ValidateDomain legacy v1 = %v, want ErrDomain", err)
	}
}

func TestValidateDomainZeroizesUnwrappedDEK(t *testing.T) {
	wrapper := &capturingWrapper{}
	domain := []byte("tenant:a:generation:1")
	sealed, err := seal.SealDomain(wrapper, []byte("payload"), nil, domain)
	if err != nil {
		t.Fatalf("SealDomain: %v", err)
	}
	wrapper.unwrapped = nil
	if err := seal.ValidateDomain(wrapper, sealed, domain); err != nil {
		t.Fatalf("ValidateDomain: %v", err)
	}
	if len(wrapper.unwrapped) == 0 ||
		!bytes.Equal(wrapper.unwrapped, make([]byte, len(wrapper.unwrapped))) {
		t.Fatal("ValidateDomain did not zeroize the unwrapped DEK")
	}
}

type capturingWrapper struct {
	wrapped   []byte
	unwrapped []byte
}

func (w *capturingWrapper) WrapDEK(dek []byte) ([]byte, error) {
	w.wrapped = append([]byte(nil), dek...)
	return append([]byte(nil), dek...), nil
}

func (w *capturingWrapper) UnwrapDEK(wrapped []byte) ([]byte, error) {
	w.unwrapped = append([]byte(nil), wrapped...)
	return w.unwrapped, nil
}

type copyingWrapper struct{}

func (*copyingWrapper) WrapDEK(dek []byte) ([]byte, error) {
	return append([]byte(nil), dek...), nil
}

func (*copyingWrapper) UnwrapDEK(wrapped []byte) ([]byte, error) {
	return append([]byte(nil), wrapped...), nil
}
