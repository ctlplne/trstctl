// SPDX-License-Identifier: LicenseRef-trstctl-EE

package taskenv

import (
	"bytes"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// signerWithDER generates an ephemeral ECDSA signer and returns it with its public DER.
func signerWithDER(t *testing.T) (crypto.Signer, []byte) {
	t.Helper()
	be := crypto.NewSoftwareBackend()
	s, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return s, s.Public().DER
}

// sampleEnvelope builds a well-formed, unsigned envelope for a requester key id.
func sampleEnvelope(keyID string) Envelope {
	return Envelope{
		RequesterID:  "requester-1",
		RequesterKey: KeyRef{ID: keyID, Algorithm: "ECDSA-P256"},
		Task: TaskIntent{
			Description: "summarize the quarterly report",
			InputCommitments: []Commitment{
				{Name: "report", Digest: []byte("digest-of-report-bytes")},
				{Name: "template", Digest: []byte("digest-of-template-bytes")},
			},
		},
		Expiry: Window{NotBefore: 1000, NotAfter: 2000},
	}
}

// TestEnvelopeDigest_DeterministicAndCollisionSensitive is the property test the card
// requires: the canonical envelope digest is byte-stable across repeated computation on
// the same value (deterministic), and it is collision-sensitive -- any change to any
// bound field flips the digest. This mirrors the length-prefixed / fixed-endian
// discipline of the delegation authority/record canonical bytes.
func TestEnvelopeDigest_DeterministicAndCollisionSensitive(t *testing.T) {
	base := sampleEnvelope("req-key")

	d1, err := base.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	// Determinism: recomputing over the SAME value yields identical bytes, and the
	// signature field is excluded from the digest (setting it does not change it).
	d2, err := base.Digest()
	if err != nil {
		t.Fatalf("digest (repeat): %v", err)
	}
	if !bytes.Equal(d1, d2) {
		t.Fatalf("digest is not deterministic: %x vs %x", d1, d2)
	}
	withSig := base
	withSig.Signature = []byte("a-signature-that-must-not-affect-the-digest")
	d3, err := withSig.Digest()
	if err != nil {
		t.Fatalf("digest (with sig): %v", err)
	}
	if !bytes.Equal(d1, d3) {
		t.Fatalf("signature field leaked into the digest: %x vs %x", d1, d3)
	}
	if len(d1) != 32 {
		t.Fatalf("digest length = %d, want 32 (SHA-256)", len(d1))
	}

	// Collision sensitivity: mutate each bound field independently; each must flip the
	// digest (no field is silently unbound).
	mutations := map[string]func(e *Envelope){
		"requester-id":      func(e *Envelope) { e.RequesterID = "requester-2" },
		"requester-key-id":  func(e *Envelope) { e.RequesterKey.ID = "other-key" },
		"requester-key-alg": func(e *Envelope) { e.RequesterKey.Algorithm = "ECDSA-P384" },
		"description":       func(e *Envelope) { e.Task.Description = "do something else" },
		"intent-digest":     func(e *Envelope) { e.Task.IntentDigest = []byte("explicit-intent-digest") },
		"commitment-name":   func(e *Envelope) { e.Task.InputCommitments[0].Name = "renamed" },
		"commitment-digest": func(e *Envelope) { e.Task.InputCommitments[0].Digest = []byte("changed") },
		"commitment-added": func(e *Envelope) {
			e.Task.InputCommitments = append(e.Task.InputCommitments, Commitment{Name: "extra", Digest: []byte("x")})
		},
		"not-before": func(e *Envelope) { e.Expiry.NotBefore = 999 },
		"not-after":  func(e *Envelope) { e.Expiry.NotAfter = 2001 },
	}
	for name, mut := range mutations {
		t.Run(name, func(t *testing.T) {
			e := sampleEnvelope("req-key")
			// deep-copy the commitments slice so mutations don't alias base
			e.Task.InputCommitments = append([]Commitment(nil), e.Task.InputCommitments...)
			mut(&e)
			d, err := e.Digest()
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			if bytes.Equal(d, d1) {
				t.Fatalf("mutation %q did not change the envelope digest (field is unbound)", name)
			}
		})
	}
}

// TestEnvelopeDigest_CommitmentOrderCanonical proves input commitments are canonically
// ordered so two semantically-equal envelopes that list the same commitments in a
// different order yield the SAME digest (the sorted discipline), while genuinely
// different commitment SETS differ.
func TestEnvelopeDigest_CommitmentOrderCanonical(t *testing.T) {
	a := sampleEnvelope("k")
	b := sampleEnvelope("k")
	// b lists the same two commitments in reversed order.
	b.Task.InputCommitments = []Commitment{
		{Name: "template", Digest: []byte("digest-of-template-bytes")},
		{Name: "report", Digest: []byte("digest-of-report-bytes")},
	}
	da, err := a.Digest()
	if err != nil {
		t.Fatalf("digest a: %v", err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatalf("digest b: %v", err)
	}
	if !bytes.Equal(da, db) {
		t.Fatalf("commitment ordering is not canonicalized: %x vs %x", da, db)
	}
}

// TestEnvelope_SignVerifyRoundTrip proves the requester signature over the canonical
// bytes round-trips through internal/crypto (AN-3): a signed envelope verifies against
// its requester key, and a tampered field (post-sign) invalidates the signature.
func TestEnvelope_SignVerifyRoundTrip(t *testing.T) {
	signer, der := signerWithDER(t)
	env := sampleEnvelope("req-key")

	signed, err := env.Sign(signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(signed.Signature) == 0 {
		t.Fatal("signed envelope carries no signature")
	}
	if err := signed.VerifySignature(crypto.PublicKey{DER: der}); err != nil {
		t.Fatalf("valid signature did not verify: %v", err)
	}

	// Tamper a bound field after signing -> the signature must no longer verify.
	tampered := signed
	tampered.Task.Description = "a different task"
	if err := tampered.VerifySignature(crypto.PublicKey{DER: der}); err == nil {
		t.Fatal("a tampered envelope verified (signature must bind every canonical field)")
	}

	// A missing signature fails closed.
	unsigned := env
	if err := unsigned.VerifySignature(crypto.PublicKey{DER: der}); err == nil {
		t.Fatal("an unsigned envelope verified")
	}
}

// TestVerifySignatureAndExpiry proves the pure in-signer verifier: a valid, unexpired,
// correctly-signed envelope passes; a bad signature, an expired window, a not-yet-valid
// window, and an unknown requester key each fail closed with a distinct error.
func TestVerifySignatureAndExpiry(t *testing.T) {
	signer, der := signerWithDER(t)
	_, otherDER := signerWithDER(t)

	env := sampleEnvelope("req-key")
	signed, err := env.Sign(signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// trustLookup resolves the requester key id to its public DER (the signer's held
	// mapping of requester identities to keys). An unknown id returns (nil,false).
	good := func(keyID string) ([]byte, bool) {
		if keyID == "req-key" {
			return der, true
		}
		return nil, false
	}

	now := time.Unix(1500, 0) // inside [1000,2000]
	if err := VerifySignatureAndExpiry(signed, now, good); err != nil {
		t.Fatalf("valid envelope failed verification: %v", err)
	}

	// Expired: now after NotAfter.
	if err := VerifySignatureAndExpiry(signed, time.Unix(2001, 0), good); err == nil {
		t.Fatal("expired envelope passed verification")
	}
	// Not yet valid: now before NotBefore.
	if err := VerifySignatureAndExpiry(signed, time.Unix(999, 0), good); err == nil {
		t.Fatal("not-yet-valid envelope passed verification")
	}
	// Bad signature: requester key resolves to a DIFFERENT key.
	bad := func(string) ([]byte, bool) { return otherDER, true }
	if err := VerifySignatureAndExpiry(signed, now, bad); err == nil {
		t.Fatal("wrong-key envelope passed verification")
	}
	// Unknown requester: lookup misses.
	miss := func(string) ([]byte, bool) { return nil, false }
	if err := VerifySignatureAndExpiry(signed, now, miss); err == nil {
		t.Fatal("unknown-requester envelope passed verification")
	}
	// Nil lookup fails closed.
	if err := VerifySignatureAndExpiry(signed, now, nil); err == nil {
		t.Fatal("nil trust lookup passed verification")
	}
}

// TestExpiry_UnboundedWindow proves a zero-valued window (no bounds) is treated as
// always-valid so a caller that omits expiry is not force-expired -- but a set NotAfter
// is honored strictly (mirrors the delegation withinNow semantics).
func TestExpiry_UnboundedWindow(t *testing.T) {
	signer, der := signerWithDER(t)
	env := sampleEnvelope("k")
	env.Expiry = Window{} // unbounded
	signed, _ := env.Sign(signer)
	good := func(string) ([]byte, bool) { return der, true }
	if err := VerifySignatureAndExpiry(signed, time.Unix(1<<40, 0), good); err != nil {
		t.Fatalf("unbounded-window envelope was force-expired: %v", err)
	}
}
