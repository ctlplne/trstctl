// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"encoding/hex"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// fixedFields returns a deterministic set of commitment fields (no keys) used for
// canonical-encoding tests.
func fixedFields() CommitmentFields {
	return CommitmentFields{
		DeploymentScope:  "spiffe://trust-domain.example",
		IdentityID:       "spiffe://trust-domain.example/db",
		TenantID:         "11111111-1111-1111-1111-111111111111",
		PredecessorEpoch: 0,
		Epoch:            1,
		PredecessorAlg:   crypto.RSA2048,
		PredecessorPub:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
		SuccessorAlg:     crypto.Ed25519,
		SuccessorPub:     []byte{0x01, 0x02, 0x03, 0x04},
		PolicyRef:        "sha256:policyref",
		HashAlg:          HashAlgSHA256,
		NotBefore:        1000,
		NotAfter:         2000,
	}
}

// TestCommitment_CanonicalStable: the commitment is a deterministic function of
// the bound fields — identical bytes across runs (INV-11). The golden hex freezes
// the encoding so an accidental change to field order/framing is caught.
func TestCommitment_CanonicalStable(t *testing.T) {
	const wantHex = "86ffbe67d1d06361757e8f2957f2ecb71afd87c93020232dca4647a505a91f7b"
	a, err := Commit(fixedFields())
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Determinism: an independently constructed identical field set commits equal.
	b, err := Commit(fixedFields())
	if err != nil {
		t.Fatalf("Commit(2): %v", err)
	}
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Fatalf("commitment not deterministic: %x != %x", a, b)
	}
	if len(a) != 32 {
		t.Fatalf("commitment length = %d, want 32 (SHA-256)", len(a))
	}
	got := hex.EncodeToString(a)
	if wantHex != "GOLDEN" && got != wantHex {
		t.Fatalf("commitment golden mismatch:\n got %s\nwant %s", got, wantHex)
	}
	t.Logf("CANONICAL_COMMITMENT=%s", got)
}

// TestCommitment_AliasRejected: only registry identifiers are accepted; free-form
// aliases cannot form a commitment or collide with a canonical id (INV-11).
func TestCommitment_AliasRejected(t *testing.T) {
	for _, alias := range []crypto.Algorithm{"P-256", "prime256v1", "secp256r1", "ed25519", "RSA", ""} {
		if _, err := registryID(alias); err == nil {
			t.Fatalf("registryID(%q) accepted an alias/unknown identifier", alias)
		}
	}
	// A commitment whose successor alg is an alias fails to form.
	f := fixedFields()
	f.SuccessorAlg = "prime256v1"
	if _, err := Commit(f); err == nil {
		t.Fatal("Commit accepted an alias successor algorithm")
	}
	// Distinct canonical algorithms yield distinct commitments.
	f1 := fixedFields()
	f1.SuccessorAlg = crypto.ECDSAP256
	f2 := fixedFields()
	f2.SuccessorAlg = crypto.ECDSAP384
	c1, err := Commit(f1)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Commit(f2)
	if err != nil {
		t.Fatal(err)
	}
	if string(c1) == string(c2) {
		t.Fatal("distinct algorithms produced equal commitments")
	}
}

// TestCommitment_DeploymentScoped: the deployment scope is bound in the
// commitment, so records from a different deployment do not verify (INV-5 /
// claim 7).
func TestCommitment_DeploymentScoped(t *testing.T) {
	a := fixedFields()
	a.DeploymentScope = "spiffe://deployment-a"
	b := fixedFields()
	b.DeploymentScope = "spiffe://deployment-b"
	ca, err := Commit(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := Commit(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) == string(cb) {
		t.Fatal("differing deployment scope produced equal commitments")
	}

	// A record minted under scope A does not verify if presented as scope B: the
	// signatures were over A's commitment, so recomputing under B fails.
	be := crypto.NewSoftwareBackend()
	sample, err := BuildSampleChain(be, "spiffe://deployment-a", "spiffe://deployment-a/db", "tenant-a")
	if err != nil {
		t.Fatalf("BuildSampleChain: %v", err)
	}
	rec := sample.Records[0]
	if err := VerifyRecord(rec); err != nil {
		t.Fatalf("valid record failed to verify: %v", err)
	}
	rec.Fields.DeploymentScope = "spiffe://deployment-b"
	if err := VerifyRecord(rec); err == nil {
		t.Fatal("record verified under a foreign deployment scope")
	}
}
