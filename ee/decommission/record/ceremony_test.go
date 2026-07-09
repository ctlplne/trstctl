// SPDX-License-Identifier: LicenseRef-trstctl-EE

package record

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/crypto"
)

func TestCeremony_BundleVerifiedAndReplayed(t *testing.T) {
	ctx := context.Background()
	policy := ceremonyPolicy()
	signer := newTestCeremonySigner(t, policy)
	bundle := newTestCeremonyBundle(t, signer)
	sink := gate.NewMemorySink()
	minter := newTestMinter(t)

	rec, event, err := ReconcileCeremonyBundle(ctx, minter, bundle, signer.PublicKey(), policy, sink)
	if err != nil {
		t.Fatalf("ReconcileCeremonyBundle: %v", err)
	}
	if event.Type != gate.TypeCeremonyBundleReplayed || event.TenantID != bundle.TenantID {
		t.Fatalf("replayed event = %+v, want ceremony replay event for tenant", event)
	}
	if got := len(sink.Events()); got != 1 {
		t.Fatalf("sink events = %d, want one verified replay", got)
	}
	if err := VerifyRecord(rec, minter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord minted from ceremony: %v", err)
	}
	if rec.Commitment.QuorumEvidence == nil || rec.Commitment.QuorumEvidence.Threshold != 2 || rec.Commitment.QuorumEvidence.ApprovalCount != 2 {
		t.Fatalf("ceremony record quorum evidence = %+v, want bound threshold evidence", rec.Commitment.QuorumEvidence)
	}
	if rec.Commitment.DestructionEvidence.Kind != gate.TypeCustodyHSMDestroyed || rec.Commitment.AuditChainHead != bundle.AuditChainHead {
		t.Fatalf("ceremony record commitment = %+v, want destroy evidence and audit head from bundle", rec.Commitment)
	}
}

func TestCeremony_FailedBundleRejectedNotReplayed(t *testing.T) {
	ctx := context.Background()
	policy := ceremonyPolicy()
	signer := newTestCeremonySigner(t, policy)
	bundle := newTestCeremonyBundle(t, signer)
	bundle.DestructionEvidence.Record = []byte("tampered destroy attestation")
	sink := gate.NewMemorySink()
	minter := newTestMinter(t)

	if _, _, err := ReconcileCeremonyBundle(ctx, minter, bundle, signer.PublicKey(), policy, sink); err == nil {
		t.Fatal("ReconcileCeremonyBundle tampered bundle succeeded, want rejection")
	}
	if got := len(sink.Events()); got != 0 {
		t.Fatalf("sink events after rejected bundle = %d, want 0", got)
	}
	if got := len(minter.minted); got != 0 {
		t.Fatalf("minted records after rejected bundle = %d, want 0", got)
	}
}

func ceremonyPolicy() gate.QuorumPolicy {
	return gate.QuorumPolicy{
		"root-ca": breakglass.Quorum{
			Threshold: 2,
			Operators: []string{"alice", "bob", "carol"},
		},
	}
}

func newTestCeremonySigner(t *testing.T, policy gate.QuorumPolicy) *gate.CeremonySigner {
	t.Helper()
	signer, err := gate.NewCeremonySigner(gate.CeremonyConfig{
		SignerID:     "test-vdec-ceremony-signer",
		Algorithm:    crypto.ECDSAP256,
		QuorumPolicy: policy,
		Now:          func() time.Time { return time.Unix(1800000700, 0) },
	})
	if err != nil {
		t.Fatalf("NewCeremonySigner: %v", err)
	}
	t.Cleanup(signer.Destroy)
	return signer
}

func newTestCeremonyBundle(t *testing.T, signer *gate.CeremonySigner) gate.CeremonyBundle {
	t.Helper()
	approvals, err := gate.EncodeQuorumApprovals("root-ca", []string{"alice", "bob"})
	if err != nil {
		t.Fatalf("EncodeQuorumApprovals: %v", err)
	}
	bundle, err := signer.Bundle(context.Background(), gate.CeremonyRequest{
		TenantID:               "tenant-a",
		StableKeyID:            "key://tenant-a/root-ca",
		FinalEpoch:             42,
		KeyClass:               "root-ca",
		CompletionEventsDigest: []byte("completion-events-digest"),
		RequiredSetDigest:      []byte("required-set-digest"),
		DestructionEvidence: gate.DestructionEvidence{
			Kind:               gate.TypeCustodyHSMDestroyed,
			TenantID:           "tenant-a",
			StableKeyID:        "key://tenant-a/root-ca",
			FinalEpoch:         42,
			AttestationClass:   gate.ClassCertifiedHardware,
			AttestationClassID: gate.ClassCertifiedHardware.ID(),
			Record:             []byte("hsm destroy attestation statement"),
			Digest:             []byte("destruction-evidence-digest"),
		},
		AuditChainHead:  "audit-head-after-ceremony-destroy",
		QuorumApprovals: approvals,
	})
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	return bundle
}
