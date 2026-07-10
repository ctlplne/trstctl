// SPDX-License-Identifier: LicenseRef-trstctl-EE

package conformance

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"trstctl.com/trstctl/ee/rpverify"
	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
)

// ChainVector is a published, versioned conformance vector for succession-chain
// verification, consumable by external relying parties.
type ChainVector struct {
	Version         int                           `json:"version"`
	Description     string                        `json:"description"`
	TrustRootPubDER []byte                        `json:"trust_root_pub_der"`
	ExpectedTenant  string                        `json:"expected_tenant"`
	Genesis         succession.GenesisRecord      `json:"genesis"`
	Chain           []succession.SuccessionRecord `json:"chain"`
	ExpectedEpoch   uint64                        `json:"expected_epoch"`
}

const chainVectorPath = "testdata/chain_vector.json"

// buildChainVector produces a deterministic sample chain vector.
func buildChainVector(t *testing.T) ChainVector {
	t.Helper()
	sc, err := succession.BuildSampleChain(crypto.NewSoftwareBackend(), e2eScope, e2eIdentity, e2eTenant)
	if err != nil {
		t.Fatal(err)
	}
	return ChainVector{
		Version: 1, Description: "PCAS r11 succession chain — genesis + 2 dual-signed records",
		TrustRootPubDER: sc.TrustRootPubDER, ExpectedTenant: e2eTenant,
		Genesis: sc.Genesis, Chain: sc.Records, ExpectedEpoch: sc.Records[len(sc.Records)-1].Fields.Epoch,
	}
}

// TestConformance_ChainVector: the published vector verifies with ee/rpverify AND with
// an INDEPENDENT differential verifier; a tampered vector is rejected by both. Run with
// UPDATE_VECTORS=1 to (re)publish the committed vector.
func TestConformance_ChainVector(t *testing.T) {
	if os.Getenv("UPDATE_VECTORS") == "1" {
		v := buildChainVector(t)
		b, _ := json.MarshalIndent(v, "", "  ")
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(chainVectorPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(chainVectorPath)
	if err != nil {
		t.Fatalf("read %s (create it with UPDATE_VECTORS=1): %v", chainVectorPath, err)
	}
	var v ChainVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	// ee/rpverify accepts the vector.
	res, err := rpverify.Verify(rpverify.Input{TrustRootPubDER: v.TrustRootPubDER, Genesis: v.Genesis, Chain: v.Chain},
		nil, rpverify.Options{ExpectedTenant: v.ExpectedTenant})
	if err != nil {
		t.Fatalf("rpverify rejected the published vector: %v", err)
	}
	if res.Epoch != v.ExpectedEpoch {
		t.Fatalf("rpverify head epoch = %d, want %d", res.Epoch, v.ExpectedEpoch)
	}
	// The independent differential verifier agrees.
	if err := differentialVerify(v.TrustRootPubDER, v.Genesis, v.Chain); err != nil {
		t.Fatalf("differential verifier disagrees with rpverify on the vector: %v", err)
	}

	// A tampered vector is rejected by BOTH verifiers (they agree on rejection too).
	bad := append([]succession.SuccessionRecord(nil), v.Chain...)
	head := bad[len(bad)-1]
	head.Possession.Signature = append([]byte{0x00}, head.Possession.Signature...)
	bad[len(bad)-1] = head
	_, rpErr := rpverify.Verify(rpverify.Input{TrustRootPubDER: v.TrustRootPubDER, Genesis: v.Genesis, Chain: bad}, nil, rpverify.Options{ExpectedTenant: v.ExpectedTenant})
	diffErr := differentialVerify(v.TrustRootPubDER, v.Genesis, bad)
	if rpErr == nil || diffErr == nil {
		t.Fatalf("tampered vector accepted: rpverify=%v differential=%v", rpErr, diffErr)
	}
}

// differentialVerify is an INDEPENDENT re-implementation of succession-chain
// verification (it does not call succession.VerifyChain): it re-checks the genesis
// trust-root anchor, epoch monotonicity, key linkage, and both dual-attestation
// signatures over the canonical commitment. Agreement with ee/rpverify on every vector
// is the differential-conformance property (PCAS-12).
func differentialVerify(trustRootPub []byte, genesis succession.GenesisRecord, chain []succession.SuccessionRecord) error {
	gd, err := diffGenesisDigest(genesis)
	if err != nil {
		return err
	}
	if crypto.VerifyMessage(trustRootPub, gd, genesis.TrustRootAtt) != nil {
		return errors.New("diff: genesis trust-root attestation invalid")
	}
	prevEpoch, prevPub, prevAlg := genesis.Epoch, genesis.PublicKey, genesis.Algorithm
	for i, rec := range chain {
		if rec.Fields.PredecessorEpoch != prevEpoch || rec.Fields.Epoch != prevEpoch+1 {
			return fmt.Errorf("diff: record %d epoch discipline", i)
		}
		if !bytes.Equal(rec.Fields.PredecessorPub, prevPub) || rec.Fields.PredecessorAlg != prevAlg {
			return fmt.Errorf("diff: record %d linkage", i)
		}
		c, err := diffCommit(rec.Fields)
		if err != nil {
			return err
		}
		if crypto.VerifyMessage(rec.Fields.PredecessorPub, c, rec.PredecessorAtt) != nil {
			return fmt.Errorf("diff: record %d predecessor signature", i)
		}
		if rec.Possession.Kind != succession.ProofSuccessorSignature || crypto.VerifyMessage(rec.Fields.SuccessorPub, c, rec.Possession.Signature) != nil {
			return fmt.Errorf("diff: record %d possession proof", i)
		}
		// v2 consistency: the record-level fields must match the committed copies.
		if rec.Fields.CommitmentVersion >= 2 {
			if rec.RecordType != rec.Fields.RecordType ||
				!bytes.Equal(rec.AuthzDigest, rec.Fields.AuthzDigest) ||
				!bytes.Equal(rec.AttestationEvidenceDigest, rec.Fields.AttestationEvidenceDigest) ||
				rec.AttestationType != rec.Fields.AttestationType {
				return fmt.Errorf("diff: record %d v2 field mismatch", i)
			}
		}
		prevEpoch, prevPub, prevAlg = rec.Fields.Epoch, rec.Fields.SuccessorPub, rec.Fields.SuccessorAlg
	}
	return nil
}

// TestINT10_IndependentEncoderAgrees pins the differential-independence property: the
// independent encoder (diffCommit) agrees with the reference encoder (succession.Commit)
// on both v1 and v2 fields. Because diffCommit shares no code with succession.Commit, a
// bug introduced into the reference encoder would make them DISAGREE here (and on the
// published vector), rather than being silently mirrored.
func TestINT10_IndependentEncoderAgrees(t *testing.T) {
	v1 := succession.CommitmentFields{
		DeploymentScope: "d", IdentityID: "id", TenantID: "t", PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: crypto.ECDSAP256, PredecessorPub: []byte{1, 2, 3},
		SuccessorAlg: crypto.ECDSAP384, SuccessorPub: []byte{4, 5, 6},
		PolicyRef: "p", HashAlg: "SHA-256", NotBefore: 1, NotAfter: 2,
	}
	v2 := v1
	v2.CommitmentVersion = 2
	v2.RecordType = succession.RecRevocation
	v2.AuthzDigest = []byte{7}
	v2.AttestationEvidenceDigest = []byte{8}
	v2.AttestationType = "tpm"
	v2.DelegationPath = "deleg"
	for name, f := range map[string]succession.CommitmentFields{"v1": v1, "v2": v2} {
		ref, err := succession.Commit(f)
		if err != nil {
			t.Fatalf("%s reference commit: %v", name, err)
		}
		ind, err := diffCommit(f)
		if err != nil {
			t.Fatalf("%s independent commit: %v", name, err)
		}
		if !bytes.Equal(ref, ind) {
			t.Fatalf("%s: independent encoder disagrees with reference:\n ref %x\n ind %x", name, ref, ind)
		}
	}
	c1, _ := diffCommit(v1)
	c2, _ := diffCommit(v2)
	if bytes.Equal(c1, c2) {
		t.Fatal("independent v1 and v2 commitments are equal (versioning not bound)")
	}
}

// --- INDEPENDENT re-implementation of the commitment / genesis encoding (INT-10) ---
//
// diffCommit and diffGenesisDigest re-implement the canonical length-prefixed,
// domain-separated encoding (v1 and v2) and the algorithm registry from scratch —
// they do NOT call succession.Commit / succession.GenesisDigest / succession's
// algRegistry. So a bug introduced into the reference encoder would make this
// differential verifier disagree with ee/rpverify on a published vector, rather than
// being mirrored and hidden (which was the case when differentialVerify shared
// succession.Commit). They share only the SHA-256 and signature-verify primitives
// (the AN-3 crypto boundary), which are not the succession encoder.

var diffRegistry = map[crypto.Algorithm]uint64{
	crypto.RSA2048: 1, crypto.RSA3072: 2, crypto.RSA4096: 3,
	crypto.ECDSAP256: 10, crypto.ECDSAP384: 11, crypto.ECDSAP521: 12, crypto.Ed25519: 20,
	crypto.Algorithm("ML-DSA-44"): 30, crypto.Algorithm("ML-DSA-65"): 31, crypto.Algorithm("ML-DSA-87"): 32,
	crypto.Algorithm("SLH-DSA-SHA2-128s"): 33, crypto.Algorithm("SLH-DSA-SHA2-128f"): 34,
	crypto.Algorithm("SLH-DSA-SHA2-192s"): 35, crypto.Algorithm("SLH-DSA-SHA2-256s"): 36,
	crypto.Algorithm("Hybrid-Ed25519-Dilithium3"): 40, crypto.Algorithm("Hybrid-ML-DSA-44-ECDSA-P256"): 41,
	crypto.Algorithm("ML-KEM-512"): 50, crypto.Algorithm("ML-KEM-768"): 51, crypto.Algorithm("ML-KEM-1024"): 52,
}

func diffField(b *bytes.Buffer, v []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(v)))
	b.Write(l[:])
	b.Write(v)
}

func diffUint(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}

func diffCommit(f succession.CommitmentFields) ([]byte, error) {
	predID, ok := diffRegistry[f.PredecessorAlg]
	if !ok {
		return nil, fmt.Errorf("diff: predecessor alg %q not in registry", f.PredecessorAlg)
	}
	succID, ok := diffRegistry[f.SuccessorAlg]
	if !ok {
		return nil, fmt.Errorf("diff: successor alg %q not in registry", f.SuccessorAlg)
	}
	if f.HashAlg != "SHA-256" {
		return nil, fmt.Errorf("diff: unsupported hash_alg %q", f.HashAlg)
	}
	var b bytes.Buffer
	if f.CommitmentVersion >= 2 {
		diffField(&b, []byte("trstctl/pcas/succession/commitment/v2"))
		diffUint(&b, uint64(f.CommitmentVersion))
	} else {
		diffField(&b, []byte("trstctl/pcas/succession/commitment/v1"))
	}
	diffField(&b, []byte(f.DeploymentScope))
	diffField(&b, []byte(f.IdentityID))
	diffField(&b, []byte(f.TenantID))
	diffUint(&b, f.PredecessorEpoch)
	diffUint(&b, f.Epoch)
	diffUint(&b, predID)
	diffField(&b, f.PredecessorPub)
	diffUint(&b, succID)
	diffField(&b, f.SuccessorPub)
	diffField(&b, []byte(f.PolicyRef))
	diffField(&b, []byte(f.HashAlg))
	diffUint(&b, uint64(f.NotBefore))
	diffUint(&b, uint64(f.NotAfter))
	if f.CommitmentVersion >= 2 {
		diffField(&b, []byte(f.RecordType))
		diffField(&b, f.AuthzDigest)
		diffField(&b, f.AttestationEvidenceDigest)
		diffField(&b, []byte(f.AttestationType))
		diffField(&b, []byte(f.DelegationPath))
	}
	return crypto.SHA256Sum(b.Bytes()), nil
}

func diffGenesisDigest(g succession.GenesisRecord) ([]byte, error) {
	algID, ok := diffRegistry[g.Algorithm]
	if !ok {
		return nil, fmt.Errorf("diff: genesis alg %q not in registry", g.Algorithm)
	}
	var b bytes.Buffer
	diffField(&b, []byte("trstctl/pcas/succession/genesis/v1"))
	diffField(&b, []byte(g.DeploymentScope))
	diffField(&b, []byte(g.IdentityID))
	diffField(&b, []byte(g.TenantID))
	diffUint(&b, algID)
	diffField(&b, g.PublicKey)
	diffUint(&b, g.Epoch)
	return crypto.SHA256Sum(b.Bytes()), nil
}
