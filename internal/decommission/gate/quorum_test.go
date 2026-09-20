// SPDX-License-Identifier: BUSL-1.1

package gate_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/decommission/gate"
	"trstctl.com/trstctl/internal/decommission/record"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/signing"
)

const (
	quorumTenant   = "tenant-quorum"
	quorumKey      = "key://tenant-quorum/root-ca"
	quorumKeyClass = "root-ca"
	quorumEpoch    = 7
)

// Guard for VDEC-claim-11.
func TestQuorum_RequiredAndBound(t *testing.T) {
	ctx := context.Background()
	policy := gate.QuorumPolicy{
		quorumKeyClass: breakglass.Quorum{
			Threshold: 2,
			Operators: []string{"alice", "bob", "carol"},
		},
	}
	g, err := gate.New(gate.Config{
		SignerID:     "test-signer",
		Sink:         gate.NewMemorySink(),
		QuorumPolicy: policy,
		Now:          func() time.Time { return time.Unix(1800000500, 0) },
	})
	if err != nil {
		t.Fatalf("New gate: %v", err)
	}
	t.Cleanup(g.Destroy)

	dep := depstate.Dependent{Class: depstate.DependentCredential, ID: "credential:issuer-root"}
	events := []eventspec.Event{
		mustQuorumDepEvent(t, 1, depstate.DependencyRegisteredV1{TenantID: quorumTenant, KeyID: quorumKey, Dependent: dep}),
		mustQuorumDepEvent(t, 2, depstate.ReprotectionCompletedV1{TenantID: quorumTenant, KeyID: quorumKey, JobID: "job-root", Dependent: dep, SuccessorKeyID: "key://tenant-quorum/successor"}),
	}

	repeatedOperator := quorumDestroyRequest(t, events, []string{"alice", "alice"})
	if decision, err := g.VerifyGatedDestroy(ctx, repeatedOperator); !errors.Is(err, gate.ErrQuorumNotMet) || decision.Approved {
		t.Fatalf("repeated operator decision = %+v err = %v, want quorum refusal", decision, err)
	}

	authorizedQuorum := quorumDestroyRequest(t, events, []string{"bob", "alice"})
	decision, err := g.VerifyGatedDestroy(ctx, authorizedQuorum)
	if err != nil {
		t.Fatalf("VerifyGatedDestroy authorized quorum: %v", err)
	}
	if !decision.Approved {
		t.Fatalf("authorized quorum was not approved: %+v", decision)
	}
	evidence, err := gate.DecodeQuorumEvidence(decision.Authorization)
	if err != nil {
		t.Fatalf("DecodeQuorumEvidence: %v", err)
	}
	if evidence.Threshold != 2 || evidence.ApprovalCount != 2 || !evidence.Satisfied || !bytes.Equal(evidence.ApproverDigest, gate.NormalizeQuorumEvidence(evidence).ApproverDigest) {
		t.Fatalf("quorum evidence = %+v, want threshold-satisfied distinct evidence", evidence)
	}
	if got := evidence.Approvers; len(got) != 2 || got[0] != "alice" || got[1] != "bob" {
		t.Fatalf("approvers = %#v, want distinct sorted alice/bob", got)
	}

	minter, err := record.NewMinter(record.Config{
		SignerID:  "test-vdec-signer",
		Algorithm: crypto.ECDSAP256,
		Now:       func() time.Time { return time.Unix(1800000600, 0) },
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	t.Cleanup(minter.Destroy)
	rec, err := minter.Mint(ctx, record.MintRequest{
		TenantID:               quorumTenant,
		StableKeyID:            quorumKey,
		FinalEpoch:             quorumEpoch,
		CompletionEventsDigest: []byte("completion-digest"),
		RequiredSetDigest:      decision.Evidence,
		QuorumEvidence:         &evidence,
		DestructionEvidence: record.EvidenceFromDestruction(gate.DestructionEvidence{
			Kind:               gate.TypeCustodyHSMDestroyed,
			TenantID:           quorumTenant,
			StableKeyID:        quorumKey,
			FinalEpoch:         quorumEpoch,
			AttestationClass:   gate.ClassCertifiedHardware,
			AttestationClassID: gate.ClassCertifiedHardware.ID(),
			Record:             []byte("destroy attestation"),
			Digest:             []byte("destroy evidence digest"),
		}),
		AuditChainHead: "audit-head-after-destroy",
	})
	if err != nil {
		t.Fatalf("Mint with quorum evidence: %v", err)
	}
	if rec.Commitment.QuorumEvidence == nil {
		t.Fatal("record commitment did not bind quorum evidence")
	}
	wantDigest, err := gate.QuorumEvidenceDigest(evidence)
	if err != nil {
		t.Fatalf("QuorumEvidenceDigest want: %v", err)
	}
	gotDigest, err := gate.QuorumEvidenceDigest(*rec.Commitment.QuorumEvidence)
	if err != nil {
		t.Fatalf("QuorumEvidenceDigest got: %v", err)
	}
	if !bytes.Equal(gotDigest, wantDigest) {
		t.Fatal("record commitment bound different quorum evidence")
	}
	if err := record.VerifyRecord(rec, minter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord with quorum evidence: %v", err)
	}

	tampered := rec
	tamperedQuorum := *rec.Commitment.QuorumEvidence
	tamperedQuorum.Approvers = []string{"alice", "carol"}
	tampered.Commitment.QuorumEvidence = &tamperedQuorum
	if err := record.VerifyRecord(tampered, minter.PublicKey()); !errors.Is(err, record.ErrUnverified) {
		t.Fatalf("VerifyRecord tampered quorum evidence error = %v, want unverified", err)
	}
}

func TestQuorum_PublicEvidenceCanOmitOperatorIdentities(t *testing.T) {
	original := gate.QuorumEvidence{
		KeyClass: quorumKeyClass, Threshold: 2, AuthorizedCount: 3,
		Approvers: []string{"alice@example.test", "bob@example.test"},
	}
	redacted, err := gate.RedactQuorumEvidence(original)
	if err != nil {
		t.Fatal(err)
	}
	if !redacted.ApproversRedacted || len(redacted.Approvers) != 0 || redacted.ApprovalCount != 2 ||
		len(redacted.ApproverDigest) != 32 || !redacted.Satisfied {
		t.Fatalf("redacted quorum = %+v", redacted)
	}
	encoded, err := gate.EncodeQuorumEvidence(redacted)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("alice")) || bytes.Contains(encoded, []byte("bob")) {
		t.Fatalf("public quorum evidence retained operator identity: %s", encoded)
	}
	decoded, err := gate.DecodeQuorumEvidence(encoded)
	if err != nil || !decoded.ApproversRedacted || decoded.ApprovalCount != 2 {
		t.Fatalf("decode redacted quorum = %+v err=%v", decoded, err)
	}
}

func quorumDestroyRequest(t *testing.T, events []eventspec.Event, approvals []string) signing.GatedDestroyRequest {
	t.Helper()
	bound := uint64(len(events))
	bounded := gate.BoundEvents(events, bound)
	proj, err := depstate.Fold(bounded)
	if err != nil {
		t.Fatalf("Fold: %v", err)
	}
	state, ok := proj.Lookup(quorumTenant, quorumKey)
	if !ok {
		t.Fatalf("missing dependency state for quorum test")
	}
	requiredSet, err := gate.RequiredSetBytes(state)
	if err != nil {
		t.Fatalf("RequiredSetBytes: %v", err)
	}
	requiredDigest, err := gate.RequiredSetDigest(state)
	if err != nil {
		t.Fatalf("RequiredSetDigest: %v", err)
	}
	segment, err := gate.EncodeLedgerSegment(quorumEpoch, events)
	if err != nil {
		t.Fatalf("EncodeLedgerSegment: %v", err)
	}
	destroyContext, err := gate.EncodeDestroyContext(quorumKeyClass)
	if err != nil {
		t.Fatalf("EncodeDestroyContext: %v", err)
	}
	quorumApprovals, err := gate.EncodeQuorumApprovals(quorumKeyClass, approvals)
	if err != nil {
		t.Fatalf("EncodeQuorumApprovals: %v", err)
	}
	return signing.GatedDestroyRequest{
		TenantID:             quorumTenant,
		Handle:               "signer-handle-root",
		SubjectRef:           quorumKey,
		AssertedFinalEpoch:   quorumEpoch,
		LedgerPosition:       bound,
		RequiredSet:          requiredSet,
		RequiredSetDigest:    requiredDigest,
		SatisfactionEvidence: segment,
		Approvals:            quorumApprovals,
		AuditChainHead:       gate.AuditChainHead(bounded),
		Context:              destroyContext,
	}
}

func mustQuorumDepEvent(t *testing.T, seq uint64, payload depstate.Payload) eventspec.Event {
	t.Helper()
	ev, err := depstate.Encode(payload)
	if err != nil {
		t.Fatalf("depstate.Encode(%T): %v", payload, err)
	}
	ev.Sequence = seq
	ev.SchemaVersion = depstate.SchemaV1
	return ev
}
