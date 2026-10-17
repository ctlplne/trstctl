// SPDX-License-Identifier: BUSL-1.1

package depstate

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"trstctl.com/trstctl/internal/proptest"

	"trstctl.com/trstctl/internal/caevent"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
)

func TestSignerCADependencyFoldRejectsFutureMintSchema(t *testing.T) {
	event := eventspec.Event{
		Type: caevent.EventCAEndEntityIssued, SchemaVersion: 99,
		TenantID: "11111111-1111-4111-8111-111111111111", ID: "future-leaf",
		Data: []byte(`{"ca_id":"22222222-2222-4222-8222-222222222222","serial":"17"}`),
	}
	if _, err := Fold([]eventspec.Event{event}); !errors.Is(err, caevent.ErrUnknownSchemaVersion) {
		t.Fatalf("future CA mint must stop signer retirement fold, got %v", err)
	}
	for _, eventType := range CARegistrationEventTypes() {
		if !caevent.IsDependencyEvent(eventType) {
			t.Errorf("signer cut includes unvalidated CA event %s", eventType)
		}
	}
}

func TestManagedCALeafIssuanceRegistersExactRetirementDependent(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	const caID = "22222222-2222-4222-8222-222222222222"
	const leafID = "33333333-3333-4333-8333-333333333333"
	payload, err := json.Marshal(projections.CAEndEntityInventoried{
		ID: leafID, CAID: caID, Serial: "7a",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := eventspec.Event{
		Type: projections.EventCAEndEntityIssued, TenantID: tenantID,
		SchemaVersion: projections.CAEndEntityInventorySchemaVersion,
		ID:            "issued-leaf-1", Sequence: 17, Data: payload,
	}
	state, err := Fold([]eventspec.Event{event})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := state.Lookup(tenantID, caID)
	if !ok || !reflect.DeepEqual(got.Registered, []Dependent{{Class: DependentCredential, ID: leafID}}) ||
		got.LedgerPosition != 17 {
		t.Fatalf("CA key retirement lost exact issued leaf: found=%t state=%+v", ok, got)
	}
}

func TestCADependencyDerivationKeepsLegacySerialsAndPublicCASignatures(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	const caID = "22222222-2222-4222-8222-222222222222"
	encode := func(eventType string, version int, id string, data any) eventspec.Event {
		t.Helper()
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		return eventspec.Event{Type: eventType, TenantID: tenantID, ID: id, SchemaVersion: version, Data: raw}
	}
	legacy := encode(projections.EventCAEndEntityIssued, 1, "legacy-serial", map[string]string{
		"ca_id": caID, "serial": "99",
	})
	modern := encode(projections.EventCAIssuedCertificate, projections.CASecretInventorySchemaVersion,
		"pki-secret", map[string]string{"ca_id": caID, "serial": "a1"})
	child := encode(projections.EventCAIntermediateCreated, projections.CAAuthorityCreatedEventSchemaVersion,
		"child-created", map[string]string{"ca_id": "child-ca", "parent_id": caID})
	cross := encode(projections.EventCACrossSigned, 1, "cross-signed", map[string]any{
		"ca_id": caID, "target_sha256": "abcd", "cross_certificate_der": []byte("public-cross-cert"),
	})
	preparedCSR := encode(projections.EventCAIntermediateCSRIssued, 1, "offline-csr", map[string]string{
		"ca_id": caID, "csr_sha256": "efgh", "offline_root": "true",
	})
	signedCSR := encode(projections.EventCAIntermediateCSRIssued, 1, "signed-csr", map[string]string{
		"ca_id": caID, "serial": "a2", "csr_sha256": "efgh",
	})
	sequence := []eventspec.Event{legacy, modern, child, cross, preparedCSR, signedCSR}
	for i := range sequence {
		sequence[i].Sequence = uint64(i + 1)
	}
	projection, err := Fold(sequence)
	if err != nil {
		t.Fatal(err)
	}
	state, ok := projection.Lookup(tenantID, caID)
	if !ok {
		t.Fatal("CA dependency state missing")
	}
	want := []Dependent{
		{Class: DependentCredential, ID: "serial:99"},
		{Class: DependentCredential, ID: projections.SecretPKIInventoryID(modern)},
		{Class: DependentCredential, ID: "child-ca"},
		{Class: DependentCredential, ID: "cross-sign:abcd"},
		{Class: DependentCredential, ID: "serial:a2"},
	}
	if !reflect.DeepEqual(state.Registered, want) {
		t.Fatalf("CA dependency inventory = %+v, want %+v", state.Registered, want)
	}
}

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
	depIDs := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	keySuffixes := []string{"a", "b", "c"}
	for seed := int64(0); seed < 50; seed++ {
		rng := proptest.New(seed)
		var seq []eventspec.Event
		for i := 0; i < 40; i++ {
			dep := Dependent{Class: classes[rng.Intn(len(classes))], ID: depIDs[rng.Intn(len(depIDs))]}
			keyID := "key-" + keySuffixes[rng.Intn(len(keySuffixes))]
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
