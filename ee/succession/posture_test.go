// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"reflect"
	"testing"
	"trstctl.com/trstctl/ee/proptest"

	"trstctl.com/trstctl/internal/events"
)

func mustEncode(t *testing.T, p Payload) events.Event {
	t.Helper()
	e, err := Encode(p)
	if err != nil {
		t.Fatalf("Encode(%T): %v", p, err)
	}
	return e
}

// TestReplay_DeterministicPosture is the canonical guard test for PCAS-claim-10 /
// INV-10: replaying the succession ledger reconstructs the crypto-posture
// projection deterministically (PCAS-01 acceptance criterion 2).
func TestReplay_DeterministicPosture(t *testing.T) {
	sink := &MemSink{}
	seq := []Payload{
		FindingV1{IdentityID: "spiffe://acme/db", TenantID: "t1", Epoch: 0, Algorithm: "RSA2048", PublicKeyDER: []byte{0x01}},
		SuccessionV1{IdentityID: "spiffe://acme/db", TenantID: "t1", PredecessorEpoch: 0, Epoch: 1, PredecessorAlgorithm: "RSA2048", SuccessorAlgorithm: "Hybrid-Ed25519-Dilithium3", SuccessorPublicKeyDER: []byte{0x02}, AlgorithmClass: ClassHybrid},
		SuccessionV1{IdentityID: "spiffe://acme/db", TenantID: "t1", PredecessorEpoch: 1, Epoch: 2, PredecessorAlgorithm: "Hybrid-Ed25519-Dilithium3", SuccessorAlgorithm: "ML-DSA-65", SuccessorPublicKeyDER: []byte{0x03}, AlgorithmClass: ClassPurePQ},
		RetirementV1{IdentityID: "spiffe://acme/db", TenantID: "t1", Epoch: 2, RetiredAlg: "Hybrid-Ed25519-Dilithium3"},
		FindingV1{IdentityID: "spiffe://acme/api", TenantID: "t1", Epoch: 0, Algorithm: "P-256", PublicKeyDER: []byte{0x0a}},
	}
	for _, p := range seq {
		sink.Append(mustEncode(t, p))
	}

	want := Posture{
		"spiffe://acme/db":  {IdentityID: "spiffe://acme/db", TenantID: "t1", CurrentEpoch: 2, CurrentAlgorithm: "ML-DSA-65", CurrentPublicDER: []byte{0x03}, State: StatePredecessorRetired},
		"spiffe://acme/api": {IdentityID: "spiffe://acme/api", TenantID: "t1", CurrentEpoch: 0, CurrentAlgorithm: "P-256", CurrentPublicDER: []byte{0x0a}, State: StateVulnerable},
	}

	first, err := Replay(sink)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("posture mismatch:\n got %#v\nwant %#v", first, want)
	}
	// Determinism: replaying the same ledger again yields an identical projection.
	second, err := Replay(sink)
	if err != nil {
		t.Fatalf("Replay (second pass): %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("replay not deterministic:\n first %#v\nsecond %#v", first, second)
	}
}

// TestFold_IdempotentUnderDuplicateDelivery confirms the projection is
// idempotent under at-least-once/duplicate delivery, preserving INV-4
// (PCAS-01 acceptance criterion 3).
func TestFold_IdempotentUnderDuplicateDelivery(t *testing.T) {
	base := []Payload{
		FindingV1{IdentityID: "id", TenantID: "t", Algorithm: "RSA2048"},
		SuccessionV1{IdentityID: "id", TenantID: "t", PredecessorEpoch: 0, Epoch: 1, SuccessorAlgorithm: "ML-DSA-65", AlgorithmClass: ClassPurePQ},
	}
	var clean []events.Event
	for _, p := range base {
		clean = append(clean, mustEncode(t, p))
	}
	// Re-deliver the whole sequence, plus extra duplicates of the succession.
	dup := append([]events.Event{}, clean...)
	dup = append(dup, clean...)
	dup = append(dup, clean[1], clean[1])

	a, err := Fold(clean)
	if err != nil {
		t.Fatalf("Fold(clean): %v", err)
	}
	b, err := Fold(dup)
	if err != nil {
		t.Fatalf("Fold(dup): %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("duplicate delivery changed posture:\n clean %#v\n   dup %#v", a, b)
	}
}

// TestFold_EqualsReferenceUnderRandomSequences is a property test: for many
// randomly generated valid sequences, folding the persisted (encoded→decoded)
// envelopes equals an independent reference reduction over the typed payloads —
// i.e. fold(seq) == replay(persist(seq)).
func TestFold_EqualsReferenceUnderRandomSequences(t *testing.T) {
	ids := []string{"a", "b", "c"}
	for seed := int64(0); seed < 50; seed++ {
		rng := proptest.New(seed)
		var payloads []Payload
		epoch := map[string]uint64{}
		for n := 0; n < 40; n++ {
			id := ids[rng.Intn(len(ids))]
			switch rng.Intn(3) {
			case 0:
				payloads = append(payloads, FindingV1{IdentityID: id, TenantID: "t", Algorithm: "RSA2048", PublicKeyDER: []byte{byte(rng.Intn(256) & 0xFF)}})
			case 1:
				e := epoch[id] + 1
				epoch[id] = e
				payloads = append(payloads, SuccessionV1{IdentityID: id, TenantID: "t", PredecessorEpoch: e - 1, Epoch: e, SuccessorAlgorithm: "alg", SuccessorPublicKeyDER: []byte{byte(rng.Intn(256) & 0xFF)}, AlgorithmClass: ClassHybrid})
			default:
				payloads = append(payloads, RetirementV1{IdentityID: id, TenantID: "t", Epoch: epoch[id]})
			}
		}
		sink := &MemSink{}
		for _, p := range payloads {
			sink.Append(mustEncode(t, p))
		}
		got, err := Replay(sink)
		if err != nil {
			t.Fatalf("seed %d: replay: %v", seed, err)
		}
		want := referenceFold(payloads)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: fold(persist(seq)) != reference:\n got %#v\nwant %#v", seed, got, want)
		}
	}
}

// TestFold_StaleOrOutOfOrderSuccessionDoesNotRegress confirms the projection
// advances only on a STRICTLY greater algorithm-epoch, so a stale (lower-epoch)
// or an equal-epoch succession arriving after a higher one is ignored and
// posture never regresses under at-least-once / out-of-order delivery (INV-4).
// It fails if Fold used >= (equal-epoch case) or last-write-wins / no guard
// (stale case) instead of a strict >.
func TestFold_StaleOrOutOfOrderSuccessionDoesNotRegress(t *testing.T) {
	// Out-of-order delivery: epoch 2 then a stale epoch 1 for the same identity.
	// Kills the last-write-wins / no-guard mutant (epoch 1 must NOT overwrite).
	stale := []events.Event{
		mustEncode(t, SuccessionV1{IdentityID: "id", TenantID: "t", PredecessorEpoch: 1, Epoch: 2, SuccessorAlgorithm: "ML-DSA-65", SuccessorPublicKeyDER: []byte{0x20}, AlgorithmClass: ClassPurePQ}),
		mustEncode(t, SuccessionV1{IdentityID: "id", TenantID: "t", PredecessorEpoch: 0, Epoch: 1, SuccessorAlgorithm: "Ed25519", SuccessorPublicKeyDER: []byte{0x10}, AlgorithmClass: ClassClassical}),
	}
	got, err := Fold(stale)
	if err != nil {
		t.Fatalf("Fold(stale): %v", err)
	}
	if p := got["id"]; p.CurrentEpoch != 2 || p.CurrentAlgorithm != "ML-DSA-65" || p.State != StatePurePQ {
		t.Fatalf("stale succession regressed posture: got epoch=%d alg=%q state=%q, want epoch=2 alg=ML-DSA-65 state=pure_pq", p.CurrentEpoch, p.CurrentAlgorithm, p.State)
	}

	// Equal-epoch re-delivery carrying DIFFERENT content must be ignored: the
	// first epoch-2 record wins. Kills the >= mutant (which would overwrite).
	equal := []events.Event{
		mustEncode(t, SuccessionV1{IdentityID: "id2", TenantID: "t", Epoch: 2, SuccessorAlgorithm: "algA", SuccessorPublicKeyDER: []byte{0xA1}, AlgorithmClass: ClassHybrid}),
		mustEncode(t, SuccessionV1{IdentityID: "id2", TenantID: "t", Epoch: 2, SuccessorAlgorithm: "algB", SuccessorPublicKeyDER: []byte{0xB2}, AlgorithmClass: ClassPurePQ}),
	}
	got2, err := Fold(equal)
	if err != nil {
		t.Fatalf("Fold(equal): %v", err)
	}
	if p := got2["id2"]; p.CurrentAlgorithm != "algA" || p.CurrentEpoch != 2 || p.State != StateHybridActive {
		t.Fatalf("equal-epoch re-delivery overwrote posture (>= bug): got epoch=%d alg=%q state=%q, want epoch=2 alg=algA state=hybrid_active", p.CurrentEpoch, p.CurrentAlgorithm, p.State)
	}
}

// referenceFold is an independent reduction, kept separate from Fold on purpose,
// used only to cross-check the encode/decode+fold path.
func referenceFold(seq []Payload) Posture {
	p := Posture{}
	for _, pl := range seq {
		switch v := pl.(type) {
		case FindingV1:
			if cur, ok := p[v.IdentityID]; !ok {
				p[v.IdentityID] = IdentityPosture{IdentityID: v.IdentityID, TenantID: v.TenantID, CurrentEpoch: v.Epoch, CurrentAlgorithm: v.Algorithm, CurrentPublicDER: v.PublicKeyDER, State: StateVulnerable}
			} else if cur.State == StateUnknown {
				cur.State = StateVulnerable
				p[v.IdentityID] = cur
			}
		case SuccessionV1:
			cur, ok := p[v.IdentityID]
			if !ok || v.Epoch > cur.CurrentEpoch {
				st := StateActive
				switch v.AlgorithmClass {
				case ClassHybrid:
					st = StateHybridActive
				case ClassPurePQ:
					st = StatePurePQ
				}
				p[v.IdentityID] = IdentityPosture{IdentityID: v.IdentityID, TenantID: v.TenantID, CurrentEpoch: v.Epoch, CurrentAlgorithm: v.SuccessorAlgorithm, CurrentPublicDER: v.SuccessorPublicKeyDER, State: st}
			}
		case RetirementV1:
			if cur, ok := p[v.IdentityID]; ok && v.Epoch >= 1 && cur.CurrentEpoch >= v.Epoch {
				cur.State = StatePredecessorRetired
				p[v.IdentityID] = cur
			}
		}
	}
	return p
}
