// SPDX-License-Identifier: LicenseRef-trstctl-EE

package quarantine_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/quarantine"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/idem"
)

// Quarantine entry on a recorded divergence witness (XREC-claim-4).
func TestQuarantine_EnteredOnPolicy(t *testing.T) {
	log := &memoryLog{}
	mgr := quarantine.NewManager(quarantine.Options{
		Log:         log,
		Idempotency: idem.NewMemory(),
		Policy:      quarantine.ReferencePolicy("vault"),
		Now:         fixedNow,
	})

	evidence := policyViolationEvidence("tenant-a", "vault")
	decision, err := mgr.ObserveWitness(context.Background(), "idem-enter", evidence)
	if err != nil {
		t.Fatalf("ObserveWitness: %v", err)
	}
	if !decision.Entered || decision.AuthorityID != "vault" || decision.WitnessID != evidence.Body.WitnessID {
		t.Fatalf("decision = %+v, want vault quarantine for witness %s", decision, evidence.Body.WitnessID)
	}
	rec, ok := mgr.State().Lookup("tenant-a", "vault")
	if !ok || rec.State != quarantine.StateQuarantined || rec.WitnessID != evidence.Body.WitnessID {
		t.Fatalf("state = %+v ok=%v, want open quarantined record", rec, ok)
	}
	if len(log.events) != 1 || log.events[0].Type != quarantine.EventTypeEntered {
		t.Fatalf("events = %+v, want one quarantine-entered event", log.events)
	}
	var payload quarantine.Entered
	decodeEvent(t, log.events[0], &payload)
	if payload.TenantID != "tenant-a" || payload.AuthorityID != "vault" || payload.WitnessID != evidence.Body.WitnessID {
		t.Fatalf("entered payload = %+v", payload)
	}
	if payload.FromState != quarantine.StateConsistent || payload.ToState != quarantine.StateQuarantined {
		t.Fatalf("entered state transition = %s -> %s, want consistent -> quarantined", payload.FromState, payload.ToState)
	}

	presenceOnly := evidence
	presenceOnly.Body.Entries = []witness.Entry{{
		Class:            witness.ClassPresence,
		PresentAuthority: "inventory",
		RecordKey:        canon.RecordKey{TenantID: "tenant-a", RecordType: canon.RecordTypeSecretRef, StableID: "present-only"},
	}}
	presenceOnly.Body.WitnessID = hex.EncodeToString(presenceOnly.Body.WitnessHash())
	presenceOnly.Signatures[0].WitnessID = presenceOnly.Body.WitnessID
	noop, err := mgr.ObserveWitness(context.Background(), "idem-presence", presenceOnly)
	if err != nil {
		t.Fatalf("ObserveWitness presence: %v", err)
	}
	if noop.Entered {
		t.Fatalf("presence-only non-issuing inventory entered quarantine: %+v", noop)
	}
}

func TestQuarantine_IssuanceRefusedWhileOpen(t *testing.T) {
	ctx := context.Background()
	log := &memoryLog{}
	mgr := quarantine.NewManager(quarantine.Options{
		Log:         log,
		Idempotency: idem.NewMemory(),
		Policy:      quarantine.ReferencePolicy("vault"),
		Now:         fixedNow,
	})
	evidence := policyViolationEvidence("tenant-a", "vault")
	if _, err := mgr.ObserveWitness(ctx, "idem-enter", evidence); err != nil {
		t.Fatalf("ObserveWitness: %v", err)
	}

	denied, err := mgr.Admit(ctx, editionseam.AdmissionRequest{
		TenantID:       "tenant-a",
		Operation:      "issue",
		IdentityID:     "identity-1",
		IdempotencyKey: "idem-refuse-vault",
		ObservedInputs: []editionseam.ObservedStateInput{{
			AuthorityID: "vault",
			RecordKey:   "tenant-a/x509_certificate/cert-a",
			Source:      "policy",
		}},
	})
	if err != nil {
		t.Fatalf("Admit quarantined input: %v", err)
	}
	if denied.Allowed || denied.RefusalID == "" {
		t.Fatalf("decision = %+v, want recorded refusal", denied)
	}
	if countEvents(log.events, quarantine.EventTypeRefused) != 1 {
		t.Fatalf("events = %+v, want one refusal", log.events)
	}
	var refused quarantine.Refused
	decodeEvent(t, log.events[len(log.events)-1], &refused)
	if refused.TenantID != "tenant-a" || refused.AuthorityID != "vault" || refused.IdentityID != "identity-1" {
		t.Fatalf("refusal payload = %+v", refused)
	}

	allowed, err := mgr.Admit(ctx, editionseam.AdmissionRequest{
		TenantID:       "tenant-a",
		Operation:      "issue",
		IdentityID:     "identity-2",
		IdempotencyKey: "idem-allow-kms",
		ObservedInputs: []editionseam.ObservedStateInput{{
			AuthorityID: "kms",
			RecordKey:   "tenant-a/x509_certificate/cert-b",
			Source:      "policy",
		}},
	})
	if err != nil {
		t.Fatalf("Admit unrelated input: %v", err)
	}
	if !allowed.Allowed {
		t.Fatalf("decision = %+v, want unrelated operation allowed", allowed)
	}
	if countEvents(log.events, quarantine.EventTypeRefused) != 1 {
		t.Fatalf("unrelated operation recorded a refusal: %+v", log.events)
	}

	ambiguous, err := mgr.Admit(ctx, editionseam.AdmissionRequest{
		TenantID:       "tenant-a",
		Operation:      "renew",
		IdentityID:     "identity-3",
		IdempotencyKey: "idem-refuse-ambiguous",
	})
	if err != nil {
		t.Fatalf("Admit ambiguous provenance: %v", err)
	}
	if ambiguous.Allowed {
		t.Fatalf("ambiguous provenance was allowed while quarantine is open: %+v", ambiguous)
	}
	if countEvents(log.events, quarantine.EventTypeRefused) != 2 {
		t.Fatalf("ambiguous refusal not recorded: %+v", log.events)
	}
}

func policyViolationEvidence(tenantID, authorityID string) witness.Evidence {
	body := witness.Body{
		RoundID:     "round-1",
		TenantID:    tenantID,
		SpecVersion: canon.SpecVersionV1,
		DigestRefs: []witness.DigestRef{
			{AuthorityID: authorityID, DigestHash: []byte{1}},
			{AuthorityID: "kms", DigestHash: []byte{2}},
		},
		Entries: []witness.Entry{{
			Class: witness.ClassPolicyViolation,
			Policy: &witness.PolicyEvidence{
				AuthorityID:   authorityID,
				RuleID:        "issuer-profile-active",
				PolicySetHash: []byte{3},
				RecordKey:     canon.RecordKey{TenantID: tenantID, RecordType: canon.RecordTypeX509Certificate, StableID: "cert-a"},
			},
		}},
		GeneratedAt: 1800000000,
	}
	body.WitnessID = hex.EncodeToString(body.WitnessHash())
	return witness.Evidence{
		Body: body,
		Signatures: []witness.WitnessSignature{{
			WitnessID:    body.WitnessID,
			AuthorityID:  authorityID,
			ContentHash:  body.WitnessHash(),
			KeyID:        "test-witness-key",
			PublicKeyDER: []byte{1},
			Signature:    []byte{2},
			SignedAt:     1800000000,
		}},
	}
}

func fixedNow() time.Time { return time.Unix(1800000100, 0).UTC() }

type memoryLog struct {
	events []eventspec.Event
}

func (m *memoryLog) Append(_ context.Context, ev eventspec.Event) (eventspec.Event, error) {
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("event-%d", len(m.events)+1)
	}
	if ev.Time.IsZero() {
		ev.Time = fixedNow()
	}
	if ev.SchemaVersion == 0 {
		ev.SchemaVersion = eventspec.DefaultSchemaVersion
	}
	m.events = append(m.events, ev)
	return ev, nil
}

func decodeEvent(t *testing.T, ev eventspec.Event, dst any) {
	t.Helper()
	if err := json.Unmarshal(ev.Data, dst); err != nil {
		t.Fatalf("decode %s: %v", ev.Type, err)
	}
}

func countEvents(events []eventspec.Event, typ string) int {
	n := 0
	for _, ev := range events {
		if ev.Type == typ {
			n++
		}
	}
	return n
}
