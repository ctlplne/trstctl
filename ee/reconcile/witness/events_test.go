// SPDX-License-Identifier: LicenseRef-trstctl-EE

package witness_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/idem"
	"trstctl.com/trstctl/internal/signing"
)

// Mutual countersignature of the witness artifact (XREC-claim-6).
func TestWitness_MutualCountersign(t *testing.T) {
	fixture := mustSignedWitnessFixture(t)
	evidence, err := witness.EvidenceFromSignedWitness(fixture.Original)
	if err != nil {
		t.Fatalf("EvidenceFromSignedWitness: %v", err)
	}
	counter, err := witness.CounterSign(context.Background(), fixture.Client, witness.CounterSignRequest{
		Evidence:           evidence,
		Digests:            fixture.Digests(),
		AuthorityID:        "kms",
		TrustedDigestKeys:  fixture.DigestTrust,
		TrustedWitnessKeys: fixture.WitnessTrust,
	})
	if err != nil {
		t.Fatalf("CounterSign: %v", err)
	}
	if counter.AuthorityID != "kms" || counter.WitnessID != evidence.Body.WitnessID {
		t.Fatalf("counter = %+v, want kms over %s", counter, evidence.Body.WitnessID)
	}
	if !bytes.Equal(counter.ContentHash, evidence.ContentHash()) {
		t.Fatal("counter signature did not bind identical witness content")
	}
	evidence.CounterSignatures = append(evidence.CounterSignatures, counter)
	if err := witness.VerifyOffline(witness.OfflineVerifyRequest{
		Evidence:               evidence,
		Digests:                fixture.Digests(),
		TrustedDigestKeys:      fixture.DigestTrust,
		TrustedWitnessKeys:     fixture.WitnessTrust,
		RequireCountersignFrom: "kms",
	}); err != nil {
		t.Fatalf("VerifyOffline after countersign: %v", err)
	}

	log := &witnessMemoryLog{}
	recorder := witness.NewRecorder(log, idem.NewMemory())
	ev, err := recorder.RecordCountersign(context.Background(), "idem-counter", evidence, counter)
	if err != nil {
		t.Fatalf("RecordCountersign: %v", err)
	}
	if ev.Type != witness.EventTypeWitnessCountersigned || len(log.events) != 1 {
		t.Fatalf("event = %+v log=%d, want one countersign event", ev, len(log.events))
	}
	var payload witness.WitnessCountersigned
	decodeWitnessEvent(t, ev, &payload)
	if payload.AuthorityID != "kms" || payload.WitnessID != evidence.Body.WitnessID {
		t.Fatalf("countersign payload = %+v", payload)
	}
}

func TestWitness_DisputeRecorded(t *testing.T) {
	fixture := mustSignedWitnessFixture(t)
	evidence, err := witness.EvidenceFromSignedWitness(fixture.Original)
	if err != nil {
		t.Fatalf("EvidenceFromSignedWitness: %v", err)
	}
	dispute, err := witness.Dispute(context.Background(), fixture.Client, witness.DisputeRequest{
		Evidence:    evidence,
		AuthorityID: "kms",
		DigestHash:  fixture.Right.State.Digest.DigestHash,
		Reason:      "local_root_mismatch",
		DisputedAt:  1800000060,
	})
	if err != nil {
		t.Fatalf("Dispute: %v", err)
	}
	if err := dispute.Verify(fixture.WitnessTrust); err != nil {
		t.Fatalf("Verify dispute: %v", err)
	}

	log := &witnessMemoryLog{}
	recorder := witness.NewRecorder(log, idem.NewMemory())
	ev, err := recorder.RecordDispute(context.Background(), "idem-dispute", evidence, dispute)
	if err != nil {
		t.Fatalf("RecordDispute: %v", err)
	}
	if ev.Type != witness.EventTypeWitnessDisputed {
		t.Fatalf("event type = %q, want %s", ev.Type, witness.EventTypeWitnessDisputed)
	}
	var payload witness.WitnessDisputed
	decodeWitnessEvent(t, ev, &payload)
	if payload.AuthorityID != "kms" || payload.Reason != "local_root_mismatch" || payload.WitnessID != evidence.Body.WitnessID {
		t.Fatalf("dispute payload = %+v", payload)
	}
}

// The XREC ledger event vocabulary (XREC-claim-19).
func TestLedger_EventTypesPresent(t *testing.T) {
	fixture := mustSignedWitnessFixture(t)
	evidence, err := witness.EvidenceFromSignedWitness(fixture.Original)
	if err != nil {
		t.Fatalf("EvidenceFromSignedWitness: %v", err)
	}
	counter, err := witness.CounterSign(context.Background(), fixture.Client, witness.CounterSignRequest{
		Evidence:           evidence,
		Digests:            fixture.Digests(),
		AuthorityID:        "kms",
		TrustedDigestKeys:  fixture.DigestTrust,
		TrustedWitnessKeys: fixture.WitnessTrust,
	})
	if err != nil {
		t.Fatalf("CounterSign: %v", err)
	}
	dispute, err := witness.Dispute(context.Background(), fixture.Client, witness.DisputeRequest{
		Evidence:    evidence,
		AuthorityID: "kms",
		DigestHash:  fixture.Right.State.Digest.DigestHash,
		Reason:      "local_root_mismatch",
		DisputedAt:  1800000060,
	})
	if err != nil {
		t.Fatalf("Dispute: %v", err)
	}

	log := &witnessMemoryLog{}
	recorder := witness.NewRecorder(log, idem.NewMemory())
	if _, err := recorder.RecordWitness(context.Background(), "idem-record", evidence); err != nil {
		t.Fatalf("RecordWitness: %v", err)
	}
	if _, err := recorder.RecordCountersign(context.Background(), "idem-counter", evidence, counter); err != nil {
		t.Fatalf("RecordCountersign: %v", err)
	}
	if _, err := recorder.RecordDispute(context.Background(), "idem-dispute", evidence, dispute); err != nil {
		t.Fatalf("RecordDispute: %v", err)
	}
	types := []string{log.events[0].Type, log.events[1].Type, log.events[2].Type}
	want := []string{witness.EventTypeWitnessRecorded, witness.EventTypeWitnessCountersigned, witness.EventTypeWitnessDisputed}
	if !equalStrings(types, want) {
		t.Fatalf("event types = %v, want %v", types, want)
	}
	state, err := witness.FoldEvents(log.events)
	if err != nil {
		t.Fatalf("FoldEvents: %v", err)
	}
	got := state[evidence.Body.WitnessID]
	if !got.Recorded || got.CountersignedBy["kms"] == nil || got.DisputedBy["kms"] == nil {
		t.Fatalf("folded state = %+v", got)
	}
	again, err := recorder.RecordWitness(context.Background(), "idem-record", evidence)
	if err != nil {
		t.Fatalf("RecordWitness replay: %v", err)
	}
	if again.Sequence != log.events[0].Sequence || len(log.events) != 3 {
		t.Fatalf("idempotent replay appended event: replay=%+v events=%d", again, len(log.events))
	}
}

// The stored witness is self-contained (XREC-claim-15).
func TestWitness_SelfContainedStorable(t *testing.T) {
	fixture := mustSignedWitnessFixture(t)
	evidence, err := witness.EvidenceFromSignedWitness(fixture.Original)
	if err != nil {
		t.Fatalf("EvidenceFromSignedWitness: %v", err)
	}
	raw, err := evidence.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	var roundTrip witness.Evidence
	if err := json.Unmarshal(raw, &roundTrip); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	if roundTrip.Body.WitnessID != evidence.Body.WitnessID || !roundTrip.Body.VerifyWitnessID() {
		t.Fatalf("round-tripped witness id/body invalid: %+v", roundTrip.Body)
	}
	if len(roundTrip.Body.DigestRefs) != 2 || len(roundTrip.Signatures) == 0 {
		t.Fatalf("evidence = %+v, want digest refs and at least one signature", roundTrip)
	}
	for _, entry := range roundTrip.Body.Entries {
		if entry.Class == "" {
			t.Fatalf("entry lacks class: %+v", entry)
		}
		if len(entry.Inclusions) == 0 && entry.Absence == nil && entry.Staleness == nil {
			t.Fatalf("entry lacks proof/evidence material: %+v", entry)
		}
	}
}

func TestWitness_OfflineVerifiableByEitherAuthority(t *testing.T) {
	fixture := mustSignedWitnessFixture(t)
	evidence, err := witness.EvidenceFromSignedWitness(fixture.Original)
	if err != nil {
		t.Fatalf("EvidenceFromSignedWitness: %v", err)
	}
	for _, verifier := range []string{"vault", "kms"} {
		if err := witness.VerifyOffline(witness.OfflineVerifyRequest{
			Evidence:           evidence,
			Digests:            fixture.Digests(),
			TrustedDigestKeys:  fixture.DigestTrust,
			TrustedWitnessKeys: fixture.WitnessTrust,
			VerifierAuthority:  verifier,
		}); err != nil {
			t.Fatalf("VerifyOffline for %s: %v", verifier, err)
		}
	}
	broken := evidence
	broken.Body.Entries[0].Absence.TargetKeyBytes = []byte("wrong")
	if err := witness.VerifyOffline(witness.OfflineVerifyRequest{
		Evidence:           broken,
		Digests:            fixture.Digests(),
		TrustedDigestKeys:  fixture.DigestTrust,
		TrustedWitnessKeys: fixture.WitnessTrust,
	}); err == nil {
		t.Fatal("VerifyOffline accepted a bad Merkle absence proof")
	}
}

type signedWitnessFixture struct {
	Client       *signing.Client
	Left         planeFixture
	Right        planeFixture
	Original     witness.SignedWitness
	DigestTrust  map[string]crypto.PublicKey
	WitnessTrust map[string]crypto.PublicKey
}

func (f signedWitnessFixture) Digests() []digest.SignedDigest {
	return []digest.SignedDigest{f.Left.State.Digest, f.Right.State.Digest}
}

func mustSignedWitnessFixture(t *testing.T) signedWitnessFixture {
	t.Helper()
	artifactSigner, err := digest.NewArtifactSigner(digest.ArtifactSignerConfig{SignerID: "xrec-test-signer"})
	if err != nil {
		t.Fatal(err)
	}
	svc := signing.NewServer(signing.WithArtifactSigner(artifactSigner))
	client := serveSigner(t, svc)
	left := mustSignedPlane(t, client, artifactSigner.KeyID(), "tenant-a", "vault", []observedKey{
		{id: "a", label: "shared-a"},
		{id: "b", label: "left-only"},
		{id: "c", label: "shared-c"},
	})
	right := mustSignedPlane(t, client, artifactSigner.KeyID(), "tenant-a", "kms", []observedKey{
		{id: "a", label: "shared-a"},
		{id: "c", label: "shared-c"},
	})
	body, err := witness.Build(witness.BuildRequest{
		RoundID:     "round-1",
		TenantID:    "tenant-a",
		SpecVersion: canon.SpecVersionV1,
		Left:        left.State,
		Right:       right.State,
		GeneratedAt: 1800000000,
	})
	if err != nil {
		t.Fatalf("Build witness: %v", err)
	}
	original, err := witness.SignForAuthority(context.Background(), client, body, "vault", artifactSigner.WitnessKeyID())
	if err != nil {
		t.Fatalf("SignForAuthority: %v", err)
	}
	return signedWitnessFixture{
		Client:       client,
		Left:         left,
		Right:        right,
		Original:     original,
		DigestTrust:  map[string]crypto.PublicKey{artifactSigner.KeyID(): artifactSigner.Public()},
		WitnessTrust: map[string]crypto.PublicKey{artifactSigner.WitnessKeyID(): artifactSigner.WitnessPublic()},
	}
}

func mustSignedPlane(t *testing.T, client *signing.Client, keyID, tenantID, authorityID string, keys []observedKey) planeFixture {
	t.Helper()
	observed := make([]canon.ObservedRecord, 0, len(keys))
	for _, key := range keys {
		observed = append(observed, canon.ObservedRecord{
			TenantID:   tenantID,
			RecordType: canon.RecordTypeKey,
			StableID:   key.id,
			Key:        &canon.KeyIdentity{LogicalID: key.id},
			Algorithm:  "ed25519",
			Status:     canon.StatusActive,
			Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: key.id},
			Attributes: map[string]canon.Value{"label": canon.String(key.label)},
		})
	}
	set, err := canon.ReduceTenant(canon.SpecVersionV1, tenantID, observed)
	if err != nil {
		t.Fatalf("ReduceTenant: %v", err)
	}
	built, err := digest.Build(digest.BuildRequest{
		Set:         set,
		AuthorityID: authorityID,
		Rules: []digest.Rule{{
			ID:         "active-only",
			Expression: "status == active",
			Evaluate: func(r canon.CanonicalRecord) bool {
				return r.Status == canon.StatusActive
			},
		}},
		Watermark:   digest.Watermark{Position: authorityID + "-42", ObservedAt: 1799999900},
		GeneratedAt: 1800000000,
	})
	if err != nil {
		t.Fatalf("Build digest: %v", err)
	}
	signed, err := digest.Sign(context.Background(), client, built.Body, keyID)
	if err != nil {
		t.Fatalf("Sign digest: %v", err)
	}
	byID := map[string]canon.CanonicalRecord{}
	bytesByID := map[string][]byte{}
	for _, rec := range set.Records {
		byID[rec.RecordKey.StableID] = rec
		b, err := rec.CanonicalBytes()
		if err != nil {
			t.Fatalf("CanonicalBytes: %v", err)
		}
		bytesByID[rec.RecordKey.StableID] = b
	}
	return planeFixture{
		State: witness.PlaneState{
			AuthorityID: authorityID,
			Set:         set,
			Tree:        built.Tree,
			Digest:      signed,
		},
		RecordByID:    byID,
		CanonicalByID: bytesByID,
	}
}

type witnessMemoryLog struct {
	events []eventspec.Event
}

func (m *witnessMemoryLog) Append(_ context.Context, e eventspec.Event) (eventspec.Event, error) {
	e.Sequence = uint64(len(m.events) + 1)
	if e.Time.IsZero() {
		e.Time = time.Unix(1800000000+int64(e.Sequence), 0).UTC()
	}
	m.events = append(m.events, e)
	return e, nil
}

func decodeWitnessEvent(t *testing.T, e eventspec.Event, out any) {
	t.Helper()
	if err := json.Unmarshal(e.Data, out); err != nil {
		t.Fatalf("decode %s: %v\n%s", e.Type, err, e.Data)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
