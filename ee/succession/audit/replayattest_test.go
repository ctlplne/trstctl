// SPDX-License-Identifier: LicenseRef-trstctl-EE

package audit_test

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/audit"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

func buildEvents(t *testing.T) []events.Event {
	t.Helper()
	var seq []events.Event
	add := func(p succession.Payload) {
		ev, err := succession.Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		seq = append(seq, ev)
	}
	add(succession.FindingV1{IdentityID: "id1", TenantID: "t", Algorithm: "RSA2048"})
	add(succession.SuccessionV1{IdentityID: "id1", TenantID: "t", PredecessorEpoch: 0, Epoch: 1, SuccessorAlgorithm: "ML-DSA-65", AlgorithmClass: succession.ClassPurePQ})
	add(succession.FindingV1{IdentityID: "id2", TenantID: "t", Algorithm: "P-256"})
	return seq
}

// TestReplayAttestation_Verifies: the attestation binds head + offset + projection
// checkpoint; verification succeeds on an honest pairing and fails on any mismatch
// (PCAS-claim-38).
func TestReplayAttestation_Verifies(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	signer, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	seq := buildEvents(t)

	att, err := audit.BuildReplayAttestation(seq, len(seq), signer)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := audit.VerifyReplayAttestation(signer.Public().DER, att); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if err := audit.VerifyAgainstLedger(seq, att); err != nil {
		t.Fatalf("honest pairing rejected: %v", err)
	}

	// Determinism guard: the same ledger prefix yields the same head + checkpoint.
	att2, _ := audit.BuildReplayAttestation(seq, len(seq), signer)
	if !bytes.Equal(att.AuditChainHead, att2.AuditChainHead) || !bytes.Equal(att.ProjectionCheckpoint, att2.ProjectionCheckpoint) {
		t.Fatal("attestation not deterministic over a fixed prefix")
	}

	// Tampered head or projection digest breaks the signature.
	badHead := att
	badHead.AuditChainHead = append([]byte{0x00}, att.AuditChainHead...)
	if audit.VerifyReplayAttestation(signer.Public().DER, badHead) == nil {
		t.Fatal("tampered audit-chain head verified")
	}
	badProj := att
	badProj.ProjectionCheckpoint = append([]byte{0x00}, att.ProjectionCheckpoint...)
	if audit.VerifyReplayAttestation(signer.Public().DER, badProj) == nil {
		t.Fatal("tampered projection checkpoint verified")
	}

	// A tampered ledger is detected on re-verification.
	tampered := append([]events.Event{}, seq...)
	tampered[0].Data = append([]byte(nil), seq[0].Data...)
	tampered[0].Data[0] ^= 0xFF
	if audit.VerifyAgainstLedger(tampered, att) == nil {
		t.Fatal("tampered ledger accepted")
	}
	// A stale offset no longer corresponds to the attested head/projection.
	stale := att
	stale.LedgerOffset = 1
	if audit.VerifyAgainstLedger(seq, stale) == nil {
		t.Fatal("stale offset accepted")
	}
}

// TestReplayAttestation_AuditorCountersign: an independent auditor re-runs the
// replay and countersigns; a consumer then accepts without replay (PCAS-claim-38).
func TestReplayAttestation_AuditorCountersign(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	signer, _ := be.GenerateKey(crypto.ECDSAP256)
	auditor, _ := be.GenerateKey(crypto.ECDSAP256)
	seq := buildEvents(t)

	att, err := audit.BuildReplayAttestation(seq, len(seq), signer)
	if err != nil {
		t.Fatal(err)
	}
	co, err := audit.AuditorCountersign(seq, att, auditor)
	if err != nil {
		t.Fatalf("countersign: %v", err)
	}
	// Consumer accepts using only the two signatures — no ledger, no replay.
	if err := audit.VerifyReplayAttestation(signer.Public().DER, co); err != nil {
		t.Fatalf("attester signature: %v", err)
	}
	if err := audit.VerifyAuditorCountersig(auditor.Public().DER, co); err != nil {
		t.Fatalf("auditor countersignature: %v", err)
	}

	// An auditor refuses to countersign a mismatched pairing.
	bad := att
	bad.ProjectionCheckpoint = append([]byte{0x00}, att.ProjectionCheckpoint...)
	if _, err := audit.AuditorCountersign(seq, bad, auditor); err == nil {
		t.Fatal("auditor countersigned a mismatched pairing")
	}
}
