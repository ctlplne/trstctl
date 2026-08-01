// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"math/rand"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// TestEpoch_DerivedFormEqualsStored: over many random valid histories, the epoch
// derived from event history equals the stored (projected) epoch (PCAS-claim-47 /
// INV-16).
func TestEpoch_DerivedFormEqualsStored(t *testing.T) {
	ids := []string{"a", "b", "c"}
	for seed := int64(0); seed < 100; seed++ {
		rng := rand.New(rand.NewSource(seed))
		epoch := map[string]uint64{}
		sink := &MemSink{}
		for n := 0; n < 40; n++ {
			id := ids[rng.Intn(len(ids))]
			e := epoch[id] + 1
			epoch[id] = e
			ev, err := Encode(SuccessionV1{IdentityID: id, TenantID: "t", PredecessorEpoch: e - 1, Epoch: e, SuccessorAlgorithm: "alg", AlgorithmClass: ClassPurePQ})
			if err != nil {
				t.Fatal(err)
			}
			sink.Append(ev)
		}
		posture, err := Fold(sink.Events())
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			derived, err := DerivedEpoch(sink.Events(), id)
			if err != nil {
				t.Fatal(err)
			}
			if derived != posture[id].CurrentEpoch {
				t.Fatalf("seed %d id %s: derived %d != stored %d", seed, id, derived, posture[id].CurrentEpoch)
			}
		}
	}
}

// TestPostureReport_SignedAndVerifiable: a posture report is signed and verifies;
// a tampered field or wrong key is rejected (PCAS-claim-50).
func TestPostureReport_SignedAndVerifiable(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	reporter, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	p := IdentityPosture{IdentityID: "spiffe://d/db", TenantID: "t", CurrentEpoch: 2, CurrentAlgorithm: "ML-DSA-65", State: StatePurePQ}
	signed, err := SignPostureReport(reporter, BuildPostureReport(p, []byte{0xAB, 0xCD}))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPostureReport(reporter.Public().DER, signed); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	bad := signed
	bad.Algorithm = "ECDSA-P256"
	if err := VerifyPostureReport(reporter.Public().DER, bad); err == nil {
		t.Fatal("tampered report verified")
	}
	other, _ := be.GenerateKey(crypto.ECDSAP256)
	if err := VerifyPostureReport(other.Public().DER, signed); err == nil {
		t.Fatal("report verified under the wrong reporter key")
	}
}

// TestPostureReport_NoReplayNeeded: the report is verified from only the report
// bytes and the reporter key — no events, no projection replay (PCAS-claim-50).
func TestPostureReport_NoReplayNeeded(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	reporter, _ := be.GenerateKey(crypto.ECDSAP256)
	signed, err := SignPostureReport(reporter, BuildPostureReport(
		IdentityPosture{IdentityID: "id", CurrentEpoch: 3, CurrentAlgorithm: "ML-DSA-65"}, []byte{1}))
	if err != nil {
		t.Fatal(err)
	}
	// VerifyPostureReport takes only (key, report) — its signature makes replay
	// structurally impossible; here we confirm it accepts standalone.
	if err := VerifyPostureReport(reporter.Public().DER, signed); err != nil {
		t.Fatalf("standalone verification failed: %v", err)
	}
	unsigned := signed
	unsigned.Signature = nil
	if err := VerifyPostureReport(reporter.Public().DER, unsigned); err == nil {
		t.Fatal("unsigned report accepted")
	}
}
