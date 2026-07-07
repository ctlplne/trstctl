// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation_test

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/ee/agentid/delegation"
	"trstctl.com/trstctl/internal/crypto"
)

func sampleRecord() delegation.Record {
	return delegation.Record{
		TenantID:       "t1",
		DelegatorID:    "root",
		DelegatorKey:   delegation.KeyRef{ID: "key-root", Algorithm: "Ed25519"},
		DelegateID:     "manager",
		Authority:      delegation.Authority{Scopes: []string{"read", "write"}, Tools: []string{"fs.read"}, Spend: delegation.Budget{Amount: 100, Currency: "USD"}, Rate: delegation.Rate{Limit: 10, Per: "minute"}, Depth: 3, Validity: delegation.Window{NotBefore: 1, NotAfter: 100}},
		DepthRemaining: 3,
		Validity:       delegation.Window{NotBefore: 1, NotAfter: 100},
		RootAnchor:     true,
		TaskDigest:     []byte{0xaa, 0xbb},
	}
}

// TestRecord_CanonicalSerializationDeterministic asserts the record's canonical
// serialization and digest are stable across calls and independent of set spelling,
// so the parent-hash linkage and the delegator signature are over reproducible bytes
// (card §3.1).
func TestRecord_CanonicalSerializationDeterministic(t *testing.T) {
	r := sampleRecord()
	b1, err := r.CanonicalBytes(reg)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	b2, err := r.CanonicalBytes(reg)
	if err != nil {
		t.Fatalf("CanonicalBytes (2nd): %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("record canonical bytes not stable across calls")
	}

	// Re-spelling the authority set (reorder scopes, dup) must not change the digest.
	r2 := sampleRecord()
	r2.Authority.Scopes = []string{"write", "read", "read"}
	d1, err := r.Digest(reg)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	d2, err := r2.Digest(reg)
	if err != nil {
		t.Fatalf("Digest r2: %v", err)
	}
	if !bytes.Equal(d1, d2) {
		t.Fatalf("record digest changed under semantically-equal authority spelling")
	}
	if len(d1) != 32 {
		t.Fatalf("digest length = %d, want 32 (SHA-256)", len(d1))
	}
}

// TestRecord_RootAnchorVsParentHash asserts a root-anchored record carries no parent
// hash and validates, while a non-root record with neither a parent hash nor the
// root-anchor marker is rejected, and the two forms produce distinct digests (§3.1).
func TestRecord_RootAnchorVsParentHash(t *testing.T) {
	root := sampleRecord() // RootAnchor: true, ParentDigest: nil
	if err := root.ValidateLinkage(); err != nil {
		t.Fatalf("root-anchored record rejected: %v", err)
	}

	child := sampleRecord()
	child.RootAnchor = false
	child.ParentDigest = []byte{0x01, 0x02, 0x03}
	if err := child.ValidateLinkage(); err != nil {
		t.Fatalf("child with parent hash rejected: %v", err)
	}

	// Neither marker nor parent hash: dangling, must be rejected.
	dangling := sampleRecord()
	dangling.RootAnchor = false
	dangling.ParentDigest = nil
	if err := dangling.ValidateLinkage(); err == nil {
		t.Fatalf("dangling record (no root anchor, no parent) accepted; want error")
	}

	// Both markers set at once is contradictory, must be rejected.
	both := sampleRecord()
	both.RootAnchor = true
	both.ParentDigest = []byte{0x09}
	if err := both.ValidateLinkage(); err == nil {
		t.Fatalf("record with both root anchor and parent hash accepted; want error")
	}

	// Root and child digests differ (linkage is bound into the canonical bytes).
	rd, _ := root.Digest(reg)
	cd, _ := child.Digest(reg)
	if bytes.Equal(rd, cd) {
		t.Fatalf("root-anchored and parent-linked records share a digest; linkage not bound")
	}
}

// TestRecord_SignVerifyOverCanonical asserts the delegator signature is over the
// canonical serialization and verifies, and that tampering the authority set breaks
// verification (§3.1). It uses a test Ed25519 signer routed through internal/crypto.
func TestRecord_SignVerifyOverCanonical(t *testing.T) {
	signer := newTestSigner(t)
	r := sampleRecord()

	signed, err := r.Sign(signer, reg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signed.Signature) == 0 {
		t.Fatalf("Sign produced an empty signature")
	}
	if err := signed.Verify(signer.Public(), reg); err != nil {
		t.Fatalf("Verify(untampered): %v", err)
	}

	// Tamper: broaden the authority after signing; verification must fail.
	tampered := signed
	tampered.Authority.Spend.Amount = 999999
	if err := tampered.Verify(signer.Public(), reg); err == nil {
		t.Fatalf("Verify(tampered authority) = nil; want failure")
	}
}

// newTestSigner returns a software Ed25519 signer built through the internal/crypto
// AN-3 boundary (no direct crypto/* import from this package).
func newTestSigner(t *testing.T) crypto.Signer {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return s
}
