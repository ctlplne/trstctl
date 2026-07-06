// SPDX-License-Identifier: LicenseRef-trstctl-EE

package conformance

import (
	"bytes"
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
	gd, err := succession.GenesisDigest(genesis)
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
		c, err := succession.Commit(rec.Fields)
		if err != nil {
			return err
		}
		if crypto.VerifyMessage(rec.Fields.PredecessorPub, c, rec.PredecessorAtt) != nil {
			return fmt.Errorf("diff: record %d predecessor signature", i)
		}
		if rec.Possession.Kind != succession.ProofSuccessorSignature || crypto.VerifyMessage(rec.Fields.SuccessorPub, c, rec.Possession.Signature) != nil {
			return fmt.Errorf("diff: record %d possession proof", i)
		}
		prevEpoch, prevPub, prevAlg = rec.Fields.Epoch, rec.Fields.SuccessorPub, rec.Fields.SuccessorAlg
	}
	return nil
}
