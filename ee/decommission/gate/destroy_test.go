// SPDX-License-Identifier: LicenseRef-trstctl-EE

package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestDestroy_ZeroizeLockedBuffers(t *testing.T) {
	ctx := context.Background()
	sink := NewMemorySink()
	destroyer := NewSoftwareCustodyDestroyer(DestroyConfig{
		SignerID: "test-signer",
		Sink:     sink,
		Now:      func() time.Time { return time.Unix(1800000100, 0) },
	})

	first, err := secret.NewFrom([]byte("root-key-material-v1"))
	if err != nil {
		t.Fatalf("NewFrom first: %v", err)
	}
	second, err := secret.NewFrom([]byte("root-key-material-v3"))
	if err != nil {
		t.Fatalf("NewFrom second: %v", err)
	}
	var inspected int
	destroyer.afterWipe = func(ref SoftwareBuffer) {
		inspected++
		for i, v := range ref.Buffer.Bytes() {
			if v != 0 {
				t.Fatalf("buffer byte %d after wipe = %d, want zero", i, v)
			}
		}
	}

	req := SoftwareDestroyRequest{
		TenantID:    testTenant,
		StableKeyID: testKey,
		FinalEpoch:  testEpoch,
		Buffers: []SoftwareBuffer{
			{Epoch: 1, Buffer: first},
			{Epoch: testEpoch, Buffer: second},
		},
		SealedCopies: []SealedCopyDisposition{{ID: "sealed-root-v3", Erased: true, KEKRotated: true}},
	}
	evidence, err := destroyer.Destroy(ctx, req)
	if err != nil {
		t.Fatalf("Destroy software: %v", err)
	}
	if evidence.Kind != TypeCustodyZeroized || evidence.AttestationClass != ClassSoftwareZeroize || evidence.AttestationClassID != ClassSoftwareZeroize.ID() {
		t.Fatalf("evidence = %+v, want software zeroization evidence", evidence)
	}
	if inspected != 2 {
		t.Fatalf("inspected wiped buffers = %d, want 2", inspected)
	}
	if first.Bytes() != nil || second.Bytes() != nil || first.Len() != 0 || second.Len() != 0 {
		t.Fatal("software destroy did not release the locked buffers")
	}
	if len(evidence.Digest) == 0 || len(evidence.Record) == 0 {
		t.Fatal("software destroy returned empty evidence")
	}

	events := sink.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d, want one zeroization record", len(events))
	}
	if events[0].Type != TypeCustodyZeroized {
		t.Fatalf("event type = %q, want %q", events[0].Type, TypeCustodyZeroized)
	}
	var record SoftwareZeroizationRecord
	if err := json.Unmarshal(events[0].Data, &record); err != nil {
		t.Fatalf("decode zeroization record: %v", err)
	}
	if record.BufferCount != 2 || record.Disposition != DispositionZeroized || record.AttestationClassID != ClassSoftwareZeroize.ID() || len(record.SealedCopies) != 1 || !record.SealedCopies[0].Erased {
		t.Fatalf("zeroization record = %+v, want two buffers and erased sealed copy", record)
	}

	again, err := destroyer.Destroy(ctx, req)
	if err != nil {
		t.Fatalf("Destroy software second call: %v", err)
	}
	if !bytes.Equal(again.Digest, evidence.Digest) {
		t.Fatal("idempotent destroy returned different evidence digest")
	}
	if got := len(sink.Events()); got != 1 {
		t.Fatalf("idempotent destroy appended %d events, want still 1", got)
	}

	bad, err := secret.NewFrom([]byte("keep-before-valid-evidence"))
	if err != nil {
		t.Fatalf("NewFrom bad: %v", err)
	}
	defer bad.Destroy()
	_, err = destroyer.Destroy(ctx, SoftwareDestroyRequest{
		TenantID:    testTenant,
		StableKeyID: "key://tenant-a/invalid",
		FinalEpoch:  testEpoch,
		Buffers:     []SoftwareBuffer{{Epoch: 1, Buffer: bad}},
		SealedCopies: []SealedCopyDisposition{
			{ID: "sealed-copy-not-erased", Erased: false},
		},
	})
	if !errors.Is(err, ErrInvalidDestroyEvidence) {
		t.Fatalf("Destroy invalid sealed copy error = %v, want invalid evidence", err)
	}
	if !bytes.Equal(bad.Bytes(), []byte("keep-before-valid-evidence")) {
		t.Fatal("software destroy wiped a buffer before validating sealed-copy disposition")
	}
}

func TestDestroy_HSMDestroyReturnsAttestation(t *testing.T) {
	ctx := context.Background()
	sink := NewMemorySink()
	module := &fakeHSMModule{
		attestation: HSMDestroyAttestation{
			ModuleID:         "hsm-cluster-a",
			KeyID:            "hsm-key-root",
			FinalEpoch:       testEpoch,
			AttestationClass: ClassCertifiedHardware,
			Statement:        []byte("module-signed-destroy-statement"),
			IssuedAtUnix:     1800000200,
		},
	}
	boundary := newTestHSMBoundary(t, module, sink)

	evidence, err := boundary.Destroy(ctx, HSMDestroyRequest{
		TenantID:    testTenant,
		StableKeyID: testKey,
		ModuleKeyID: "hsm-key-root",
		FinalEpoch:  testEpoch,
	})
	if err != nil {
		t.Fatalf("Destroy HSM: %v", err)
	}
	if module.calls != 1 {
		t.Fatalf("module destroy calls = %d, want 1", module.calls)
	}
	if evidence.Kind != TypeCustodyHSMDestroyed || evidence.AttestationClass != ClassCertifiedHardware || evidence.AttestationClassID != ClassCertifiedHardware.ID() {
		t.Fatalf("evidence = %+v, want certified HSM destroy evidence", evidence)
	}
	if len(evidence.Digest) == 0 || len(evidence.Record) == 0 {
		t.Fatal("HSM destroy returned empty evidence")
	}

	events := sink.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d, want one HSM destroy record", len(events))
	}
	if events[0].Type != TypeCustodyHSMDestroyed {
		t.Fatalf("event type = %q, want %q", events[0].Type, TypeCustodyHSMDestroyed)
	}
	var record HSMDestroyRecord
	if err := json.Unmarshal(events[0].Data, &record); err != nil {
		t.Fatalf("decode HSM record: %v", err)
	}
	if record.Attestation.ModuleID != "hsm-cluster-a" || record.Attestation.AttestationClassID != ClassCertifiedHardware.ID() || record.TerminalState.FinalEpoch != testEpoch {
		t.Fatalf("HSM record = %+v, want module identity, class, and terminal epoch", record)
	}
}

// Guard for VDEC-claim-13.
func TestDestroy_HSMTerminalEpochRefusesAtOrBelow(t *testing.T) {
	ctx := context.Background()
	module := &fakeHSMModule{
		attestation: HSMDestroyAttestation{
			ModuleID:         "hsm-cluster-a",
			KeyID:            "hsm-key-root",
			FinalEpoch:       testEpoch,
			AttestationClass: ClassCertifiedHardware,
			Signature:        []byte("module-signature"),
		},
	}
	boundary := newTestHSMBoundary(t, module, NewMemorySink())
	if _, err := boundary.Destroy(ctx, HSMDestroyRequest{
		TenantID:    testTenant,
		StableKeyID: testKey,
		ModuleKeyID: "hsm-key-root",
		FinalEpoch:  testEpoch,
	}); err != nil {
		t.Fatalf("Destroy HSM: %v", err)
	}

	for _, epoch := range []uint64{testEpoch - 1, testEpoch} {
		err := boundary.AuthorizeOperation(CustodyOperationRequest{
			TenantID:    testTenant,
			StableKeyID: testKey,
			Epoch:       epoch,
			Operation:   "sign",
		})
		if !errors.Is(err, ErrTerminalEpochReached) {
			t.Fatalf("AuthorizeOperation epoch %d error = %v, want terminal epoch refusal", epoch, err)
		}
	}
	if err := boundary.AuthorizeOperation(CustodyOperationRequest{
		TenantID:    testTenant,
		StableKeyID: testKey,
		Epoch:       testEpoch + 1,
		Operation:   "sign",
	}); err != nil {
		t.Fatalf("AuthorizeOperation successor epoch: %v", err)
	}
	if state, ok := boundary.TerminalEpoch(testTenant, testKey); !ok || state.FinalEpoch != testEpoch || state.ModuleID != "hsm-cluster-a" {
		t.Fatalf("terminal state = %+v ok=%v, want recorded final epoch in boundary", state, ok)
	}
}

// Guard for VDEC-claim-7.
func TestDestroy_AttestationClassMinGate(t *testing.T) {
	policy := AttestationClassPolicy{"root-ca": ClassCertifiedHardware}
	software := newDestructionEvidence(TypeCustodyZeroized, testTenant, testKey, testEpoch, ClassSoftwareZeroize, []byte("zeroized"))
	binding, err := policy.EnforceBeforeMint("root-ca", software)
	if !errors.Is(err, ErrBelowMinAttestationClass) {
		t.Fatalf("EnforceBeforeMint software error = %v, want below-min refusal", err)
	}
	if binding.EvidenceClassID != ClassSoftwareZeroize.ID() || binding.MinimumClassID != ClassCertifiedHardware.ID() {
		t.Fatalf("below-min binding = %+v, want surfaced evidence/minimum class ids", binding)
	}

	certified := newDestructionEvidence(TypeCustodyHSMDestroyed, testTenant, testKey, testEpoch, ClassCertifiedHardware, []byte("hsm-attestation"))
	binding, err = policy.EnforceBeforeMint("root-ca", certified)
	if err != nil {
		t.Fatalf("EnforceBeforeMint certified: %v", err)
	}
	if binding.EvidenceClassID != ClassCertifiedHardware.ID() || binding.MinimumClassID != ClassCertifiedHardware.ID() || binding.EvidenceDigestHex == "" {
		t.Fatalf("certified binding = %+v, want bind-ready class id and digest", binding)
	}
}

type fakeHSMModule struct {
	attestation HSMDestroyAttestation
	calls       int
	seen        HSMDestroyRequest
}

func (f *fakeHSMModule) DestroyKey(_ context.Context, req HSMDestroyRequest) (HSMDestroyAttestation, error) {
	f.calls++
	f.seen = req
	return f.attestation, nil
}

func newTestHSMBoundary(t *testing.T, module HSMDestroyModule, sink EvidenceAppendSink) *HSMCustodyBoundary {
	t.Helper()
	boundary, err := NewHSMCustodyBoundary(module, DestroyConfig{
		SignerID: "test-hsm-enforcer",
		Sink:     sink,
		Now:      func() time.Time { return time.Unix(1800000300, 0) },
	})
	if err != nil {
		t.Fatalf("NewHSMCustodyBoundary: %v", err)
	}
	return boundary
}
