// SPDX-License-Identifier: LicenseRef-trstctl-EE

package gate

import (
	"bytes"
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/signing"
)

const (
	testTenant = "tenant-a"
	testKey    = "key://tenant-a/root"
	testHandle = "signer-handle-root"
	testEpoch  = 3
)

// Guard for VDEC-claim-12.
func TestGate_RefusesDestroyUntilAllDependentsReprotected(t *testing.T) {
	ctx := context.Background()
	sink := NewMemorySink()
	g := newTestGate(t, sink)

	ciphertext := depstate.Dependent{Class: depstate.DependentCiphertext, ID: "ciphertext:bucket-a/object-1"}
	wrapped := depstate.Dependent{Class: depstate.DependentWrappedKey, ID: "wrapped-key:dek-7"}
	partial := []eventspec.Event{
		mustDepEvent(t, 1, depstate.DependencyRegisteredV1{TenantID: testTenant, KeyID: testKey, Dependent: ciphertext}),
		mustDepEvent(t, 2, depstate.DependencyRegisteredV1{TenantID: testTenant, KeyID: testKey, Dependent: wrapped}),
		mustDepEvent(t, 3, depstate.ReprotectionCompletedV1{TenantID: testTenant, KeyID: testKey, JobID: "job-ciphertext", Dependent: ciphertext, SuccessorKeyID: "key://tenant-a/successor"}),
	}

	refused, err := g.VerifyGatedDestroy(ctx, requestFromEvents(t, partial, 3))
	if err != nil {
		t.Fatalf("VerifyGatedDestroy partial: %v", err)
	}
	if refused.Approved {
		t.Fatal("gate approved while one registered dependent was unaccounted")
	}
	if len(refused.RefusalRecord) == 0 {
		t.Fatal("refusal record is empty")
	}
	if got := len(sink.Events()); got != 1 {
		t.Fatalf("refusal sink events = %d, want 1", got)
	}

	complete := append([]eventspec.Event{}, partial...)
	complete = append(complete, mustDepEvent(t, 4, depstate.ReprotectionCompletedV1{TenantID: testTenant, KeyID: testKey, JobID: "job-wrapped", Dependent: wrapped, SuccessorKeyID: "key://tenant-a/successor"}))
	approved, err := g.VerifyGatedDestroy(ctx, requestFromEvents(t, complete, 4))
	if err != nil {
		t.Fatalf("VerifyGatedDestroy complete: %v", err)
	}
	if !approved.Approved {
		t.Fatalf("gate refused after all dependents were accounted: %+v", approved)
	}
	if got := len(sink.Events()); got != 1 {
		t.Fatalf("approval appended refusal events = %d, want still 1", got)
	}
}

func TestGate_SetDifferenceEmptyRequired(t *testing.T) {
	ctx := context.Background()
	g := newTestGate(t, NewMemorySink())

	a := depstate.Dependent{Class: depstate.DependentCiphertext, ID: "ciphertext:a"}
	b := depstate.Dependent{Class: depstate.DependentCredential, ID: "credential:b"}
	extra := depstate.Dependent{Class: depstate.DependentWrappedKey, ID: "wrapped:extra"}
	nonEmptyDifference := []eventspec.Event{
		mustDepEvent(t, 1, depstate.DependencyRegisteredV1{TenantID: testTenant, KeyID: testKey, Dependent: a}),
		mustDepEvent(t, 2, depstate.DependencyRegisteredV1{TenantID: testTenant, KeyID: testKey, Dependent: b}),
		mustDepEvent(t, 3, depstate.ReprotectionCompletedV1{TenantID: testTenant, KeyID: testKey, JobID: "job-a", Dependent: a, SuccessorKeyID: "key://tenant-a/successor"}),
		mustDepEvent(t, 4, depstate.ReprotectionCompletedV1{TenantID: testTenant, KeyID: testKey, JobID: "job-extra", Dependent: extra, SuccessorKeyID: "key://tenant-a/successor"}),
	}
	refused, err := g.VerifyGatedDestroy(ctx, requestFromEvents(t, nonEmptyDifference, 4))
	if err != nil {
		t.Fatalf("VerifyGatedDestroy one missing: %v", err)
	}
	if refused.Approved {
		t.Fatal("gate approved with registered-accounted set difference {credential:b}")
	}

	emptyDifference := append([]eventspec.Event{}, nonEmptyDifference...)
	emptyDifference = append(emptyDifference, mustDepEvent(t, 5, depstate.DependencyReleasedV1{TenantID: testTenant, KeyID: testKey, Dependent: b, Reason: "expired"}))
	approved, err := g.VerifyGatedDestroy(ctx, requestFromEvents(t, emptyDifference, 5))
	if err != nil {
		t.Fatalf("VerifyGatedDestroy empty difference: %v", err)
	}
	if !approved.Approved {
		t.Fatalf("gate refused when registered-accounted difference was empty: %+v", approved)
	}
}

// Guard for VDEC-claim-21.
func TestRefusal_SignedArtifactNamesUnaccountedDependent(t *testing.T) {
	ctx := context.Background()
	sink := NewMemorySink()
	g := newTestGate(t, sink)

	blocker := depstate.Dependent{Class: depstate.DependentLeasedSecret, ID: "lease:db-creds-1"}
	events := []eventspec.Event{
		mustDepEvent(t, 1, depstate.DependencyRegisteredV1{TenantID: testTenant, KeyID: testKey, Dependent: blocker}),
	}
	decision, err := g.VerifyGatedDestroy(ctx, requestFromEvents(t, events, 1))
	if err != nil {
		t.Fatalf("VerifyGatedDestroy: %v", err)
	}
	if decision.Approved {
		t.Fatal("gate approved an unaccounted dependent")
	}

	artifact, err := DecodeRefusalArtifact(decision.RefusalRecord)
	if err != nil {
		t.Fatalf("DecodeRefusalArtifact: %v", err)
	}
	if artifact.Body.ViolatedConstraint != refusalConstraint {
		t.Fatalf("violated constraint = %q, want %q", artifact.Body.ViolatedConstraint, refusalConstraint)
	}
	if len(artifact.Body.Unaccounted) == 0 && artifact.Body.UnaccountedDigest == "" {
		t.Fatal("refusal named neither an unaccounted dependent nor its digest")
	}
	if len(artifact.Body.Unaccounted) == 0 || artifact.Body.Unaccounted[0] != blocker {
		t.Fatalf("unaccounted dependents = %#v, want first %#v", artifact.Body.Unaccounted, blocker)
	}
	if err := artifact.Verify(map[string]crypto.PublicKey{artifact.KeyID: {Algorithm: artifact.Algorithm, DER: artifact.PublicKeyDER}}); err != nil {
		t.Fatalf("refusal signature did not verify: %v", err)
	}

	appended := sink.Events()
	if len(appended) != 1 {
		t.Fatalf("refusal sink events = %d, want 1", len(appended))
	}
	if appended[0].Type != TypeGatedDestructionRefused {
		t.Fatalf("event type = %q, want %q", appended[0].Type, TypeGatedDestructionRefused)
	}
	if !bytes.Equal(appended[0].Data, decision.RefusalRecord) {
		t.Fatal("appended refusal event does not carry the signed refusal artifact")
	}
}

func newTestGate(t *testing.T, sink RefusalAppendSink) *Gate {
	t.Helper()
	g, err := New(Config{
		SignerID:  "test-signer",
		Sink:      sink,
		Now:       func() time.Time { return time.Unix(1800000000, 0) },
		Algorithm: crypto.ECDSAP256,
	})
	if err != nil {
		t.Fatalf("New gate: %v", err)
	}
	t.Cleanup(g.Destroy)
	return g
}

func requestFromEvents(t *testing.T, events []eventspec.Event, bound uint64) signing.GatedDestroyRequest {
	t.Helper()
	bounded := BoundEvents(events, bound)
	proj, err := depstate.Fold(bounded)
	if err != nil {
		t.Fatalf("Fold: %v", err)
	}
	state, ok := proj.Lookup(testTenant, testKey)
	if !ok {
		state = depstate.KeyState{TenantID: testTenant, KeyID: testKey, LedgerPosition: bound}
	}
	requiredSet, err := RequiredSetBytes(state)
	if err != nil {
		t.Fatalf("RequiredSetBytes: %v", err)
	}
	requiredDigest, err := RequiredSetDigest(state)
	if err != nil {
		t.Fatalf("RequiredSetDigest: %v", err)
	}
	segment, err := EncodeLedgerSegment(testEpoch, events)
	if err != nil {
		t.Fatalf("EncodeLedgerSegment: %v", err)
	}
	return signing.GatedDestroyRequest{
		TenantID:             testTenant,
		Handle:               testHandle,
		SubjectRef:           testKey,
		AssertedFinalEpoch:   testEpoch,
		LedgerPosition:       bound,
		RequiredSet:          requiredSet,
		RequiredSetDigest:    requiredDigest,
		SatisfactionEvidence: segment,
		AuditChainHead:       AuditChainHead(bounded),
	}
}

func mustDepEvent(t *testing.T, seq uint64, payload depstate.Payload) eventspec.Event {
	t.Helper()
	ev, err := depstate.Encode(payload)
	if err != nil {
		t.Fatalf("depstate.Encode(%T): %v", payload, err)
	}
	ev.Sequence = seq
	ev.SchemaVersion = depstate.SchemaV1
	return ev
}
