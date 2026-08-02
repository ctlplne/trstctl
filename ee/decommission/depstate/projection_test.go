// SPDX-License-Identifier: LicenseRef-trstctl-EE

package depstate

import (
	"reflect"
	"testing"
	"trstctl.com/trstctl/ee/proptest"

	"trstctl.com/trstctl/internal/eventspec"
)

func mustEncode(t *testing.T, p Payload) eventspec.Event {
	t.Helper()
	e, err := Encode(p)
	if err != nil {
		t.Fatalf("Encode(%T): %v", p, err)
	}
	return e
}

type memSink struct{ evs []eventspec.Event }

func (m *memSink) Append(e eventspec.Event) {
	if e.Sequence == 0 {
		e.Sequence = uint64(len(m.evs) + 1)
	}
	m.evs = append(m.evs, e)
}

func (m *memSink) Events() []eventspec.Event {
	out := make([]eventspec.Event, len(m.evs))
	copy(out, m.evs)
	return out
}

func replay(src *memSink) (Projection, error) {
	return Fold(src.Events())
}

func TestDepState_AssociatesAllDependentClasses(t *testing.T) {
	sink := &memSink{}
	keyID := "key://tenant-a/root"
	cases := []Dependent{
		{Class: DependentCiphertext, ID: "ciphertext:bucket-a/object-1"},
		{Class: DependentWrappedKey, ID: "wrapped-key:dek-7"},
		{Class: DependentCredential, ID: "credential:serial-99"},
		{Class: DependentLeasedSecret, ID: "lease:db-creds-1"},
		{Class: DependentDataSet, ID: "dataset:customer-archive"},
	}

	for _, dep := range cases {
		sink.Append(mustEncode(t, DependencyRegisteredV1{
			TenantID:  "tenant-a",
			KeyID:     keyID,
			Dependent: dep,
			Origin:    RegistrationOriginIssued,
		}))
	}
	sink.Append(mustEncode(t, DependencyErasureDesignatedV1{
		TenantID:       "tenant-a",
		KeyID:          keyID,
		Dependent:      cases[4],
		DesignationRef: "erasure-designation:customer-archive",
	}))

	got, err := replay(sink)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	state, ok := got.Lookup("tenant-a", keyID)
	if !ok {
		t.Fatalf("projection missing tenant-a/%s", keyID)
	}
	if !reflect.DeepEqual(state.Registered, cases) {
		t.Fatalf("registered dependents mismatch:\n got %#v\nwant %#v", state.Registered, cases)
	}
	if !reflect.DeepEqual(state.ErasureDesignated, []Dependent{cases[4]}) {
		t.Fatalf("erasure designations mismatch:\n got %#v", state.ErasureDesignated)
	}
}

// Guard for VDEC-claim-15.
func TestDepState_DeterministicReplayProjection(t *testing.T) {
	sink := &memSink{}
	events := []eventspec.Event{
		mustEncode(t, DependencyRegisteredV1{TenantID: "tenant-a", KeyID: "key-a", Dependent: Dependent{Class: DependentCiphertext, ID: "ct-1"}}),
		mustEncode(t, DependencyRegisteredV1{TenantID: "tenant-a", KeyID: "key-a", Dependent: Dependent{Class: DependentCredential, ID: "cred-1"}}),
		mustEncode(t, ReprotectionCompletedV1{TenantID: "tenant-a", KeyID: "key-a", JobID: "job-ct-1", Dependent: Dependent{Class: DependentCiphertext, ID: "ct-1"}, SuccessorKeyID: "key-b"}),
		mustEncode(t, DependencyReleasedV1{TenantID: "tenant-a", KeyID: "key-a", Dependent: Dependent{Class: DependentCredential, ID: "cred-1"}, Reason: "expired"}),
	}
	for _, e := range events {
		sink.Append(e)
	}

	first, err := replay(sink)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	second, err := replay(sink)
	if err != nil {
		t.Fatalf("Replay second pass: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("replay not deterministic:\n first %#v\nsecond %#v", first, second)
	}

	duplicated := &memSink{}
	for _, e := range sink.Events() {
		duplicated.Append(e)
		duplicated.Append(e)
	}
	withDuplicates, err := replay(duplicated)
	if err != nil {
		t.Fatalf("Replay duplicates: %v", err)
	}
	if !reflect.DeepEqual(first, withDuplicates) {
		t.Fatalf("duplicate delivery changed projection:\n clean %#v\n   dup %#v", first, withDuplicates)
	}
	state, ok := first.Lookup("tenant-a", "key-a")
	if !ok {
		t.Fatal("projection missing tenant-a/key-a")
	}
	if got := state.LedgerPosition; got != 4 {
		t.Fatalf("LedgerPosition = %d, want 4", got)
	}
}

func TestDepState_TenantScopedKeyIDsDoNotCollide(t *testing.T) {
	sink := &memSink{}
	sharedKeyID := "key://shared/logical"
	depA := Dependent{Class: DependentCiphertext, ID: "ct-a"}
	depB := Dependent{Class: DependentCredential, ID: "cred-b"}

	sink.Append(mustEncode(t, DependencyRegisteredV1{TenantID: "tenant-a", KeyID: sharedKeyID, Dependent: depA}))
	sink.Append(mustEncode(t, DependencyRegisteredV1{TenantID: "tenant-b", KeyID: sharedKeyID, Dependent: depB}))

	got, err := replay(sink)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	stateA, ok := got.Lookup("tenant-a", sharedKeyID)
	if !ok {
		t.Fatal("projection missing tenant-a state")
	}
	stateB, ok := got.Lookup("tenant-b", sharedKeyID)
	if !ok {
		t.Fatal("projection missing tenant-b state")
	}
	if !reflect.DeepEqual(stateA.Registered, []Dependent{depA}) {
		t.Fatalf("tenant-a registered = %#v, want %#v", stateA.Registered, []Dependent{depA})
	}
	if !reflect.DeepEqual(stateB.Registered, []Dependent{depB}) {
		t.Fatalf("tenant-b registered = %#v, want %#v", stateB.Registered, []Dependent{depB})
	}
}

func TestDepState_UnaccountedDependentBlocksDestroy(t *testing.T) {
	sink := &memSink{}
	keyID := "key://tenant-a/issuer"
	accountedByCompletion := Dependent{Class: DependentCiphertext, ID: "ct-1"}
	accountedByRelease := Dependent{Class: DependentCredential, ID: "cert-1"}
	accountedByErasure := Dependent{Class: DependentDataSet, ID: "dataset-1"}
	blocker := Dependent{Class: DependentWrappedKey, ID: "wrapped-1"}

	for _, dep := range []Dependent{accountedByCompletion, accountedByRelease, accountedByErasure, blocker} {
		sink.Append(mustEncode(t, DependencyRegisteredV1{TenantID: "tenant-a", KeyID: keyID, Dependent: dep}))
	}
	sink.Append(mustEncode(t, ReprotectionCompletedV1{TenantID: "tenant-a", KeyID: keyID, JobID: "job-ct-1", Dependent: accountedByCompletion, SuccessorKeyID: "key://tenant-a/successor"}))
	sink.Append(mustEncode(t, DependencyReleasedV1{TenantID: "tenant-a", KeyID: keyID, Dependent: accountedByRelease, Reason: "expired"}))
	sink.Append(mustEncode(t, DependencyErasureDesignatedV1{TenantID: "tenant-a", KeyID: keyID, Dependent: accountedByErasure, DesignationRef: "erase-1"}))

	got, err := replay(sink)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	state, ok := got.Lookup("tenant-a", keyID)
	if !ok {
		t.Fatalf("projection missing tenant-a/%s", keyID)
	}
	unaccounted := state.Unaccounted()
	if !reflect.DeepEqual(unaccounted, []Dependent{blocker}) {
		t.Fatalf("unaccounted mismatch:\n got %#v\nwant %#v", unaccounted, []Dependent{blocker})
	}
}

func TestDepState_FoldEqualsReplayOverGeneratedSequences(t *testing.T) {
	classes := []DependentClass{DependentCiphertext, DependentWrappedKey, DependentCredential, DependentLeasedSecret, DependentDataSet}
	for seed := int64(0); seed < 50; seed++ {
		rng := proptest.New(seed)
		var seq []eventspec.Event
		for i := 0; i < 40; i++ {
			dep := Dependent{Class: classes[rng.Intn(len(classes))], ID: string(rune('a' + rng.Intn(8)))}
			keyID := "key-" + string(rune('a'+rng.Intn(3)))
			switch rng.Intn(5) {
			case 0:
				seq = append(seq, mustEncode(t, DependencyReleasedV1{TenantID: "tenant-a", KeyID: keyID, Dependent: dep}))
			case 1:
				seq = append(seq, mustEncode(t, DependencyErasureDesignatedV1{TenantID: "tenant-a", KeyID: keyID, Dependent: Dependent{Class: DependentDataSet, ID: dep.ID}, DesignationRef: "erase"}))
			case 2:
				seq = append(seq, mustEncode(t, ReprotectionCompletedV1{TenantID: "tenant-a", KeyID: keyID, JobID: "job", Dependent: dep, SuccessorKeyID: "successor"}))
			case 3:
				seq = append(seq, mustEncode(t, RevocationCompletedV1{TenantID: "tenant-a", KeyID: keyID, JobID: "lease-job", Dependent: dep, Destination: "backend"}))
			default:
				seq = append(seq, mustEncode(t, DependencyRegisteredV1{TenantID: "tenant-a", KeyID: keyID, Dependent: dep, Origin: RegistrationOriginDiscovery}))
			}
		}

		sink := &memSink{}
		for _, e := range seq {
			sink.Append(e)
		}
		want, err := Fold(seq)
		if err != nil {
			t.Fatalf("seed %d: Fold: %v", seed, err)
		}
		got, err := replay(sink)
		if err != nil {
			t.Fatalf("seed %d: Replay: %v", seed, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: fold(seq) != replay(persist(seq)):\n got %#v\nwant %#v", seed, got, want)
		}
	}
}
