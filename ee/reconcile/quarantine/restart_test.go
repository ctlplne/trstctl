// SPDX-License-Identifier: LicenseRef-trstctl-EE

package quarantine_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/reconcile/quarantine"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/idem"
)

// TestQuarantine_SurvivesProcessRestart is the fail-open regression tripwire for
// AH-59cce24d. Quarantine is a containment control, so a process bounce must not
// release it. The second Manager here is a FRESH object graph over the SAME
// substrate -- the event log -- and its containment state is rebuilt only from
// xrec.quarantine.entered / xrec.quarantine.released, exactly as the core
// projector rebuilds it from sequence 0 on boot.
//
// Measured on the unpatched tree, this exact sequence returned
// `Allowed=true RefusalID="" err=<nil>`.
func TestQuarantine_SurvivesProcessRestart(t *testing.T) {
	ctx := context.Background()
	log := &memoryLog{}
	before := quarantine.NewManager(quarantine.Options{
		Log:         log,
		Idempotency: idem.NewMemory(),
		Policy:      quarantine.ReferencePolicy("vault"),
		Now:         fixedNow,
	})
	evidence := policyViolationEvidence("tenant-a", "vault")
	entered, err := before.ObserveWitness(ctx, "idem-enter", evidence)
	if err != nil {
		t.Fatalf("ObserveWitness: %v", err)
	}
	if !entered.Entered {
		t.Fatalf("decision = %+v, want an open quarantine before the restart", entered)
	}

	// ---- the restart: nothing survives except the log ----
	after := replayIntoFreshManager(t, log)

	denied, err := after.Admit(ctx, editionseam.AdmissionRequest{
		TenantID:       "tenant-a",
		Operation:      "issue",
		IdentityID:     "identity-1",
		IdempotencyKey: "idem-refuse-after-restart",
		ObservedInputs: []editionseam.ObservedStateInput{{
			AuthorityID: "vault",
			RecordKey:   "tenant-a/x509_certificate/cert-a",
			Source:      "policy",
		}},
	})
	if err != nil {
		t.Fatalf("Admit after restart: %v", err)
	}
	if denied.Allowed {
		t.Fatalf("restart un-quarantined tenant-a: decision = %+v", denied)
	}
	if denied.RefusalID == "" {
		t.Fatalf("refusal after restart was not recorded: %+v", denied)
	}

	// AN-1: the rebuilt containment state is tenant-scoped and must not leak.
	other, err := after.Admit(ctx, editionseam.AdmissionRequest{
		TenantID:       "tenant-b",
		Operation:      "issue",
		IdentityID:     "identity-2",
		IdempotencyKey: "idem-other-tenant",
		ObservedInputs: []editionseam.ObservedStateInput{{
			AuthorityID: "vault",
			RecordKey:   "tenant-b/x509_certificate/cert-b",
			Source:      "policy",
		}},
	})
	if err != nil {
		t.Fatalf("Admit unrelated tenant: %v", err)
	}
	if !other.Allowed {
		t.Fatalf("quarantine leaked across tenants: %+v", other)
	}
}

// TestQuarantine_ReleaseSurvivesProcessRestart is the other half of the fold: a
// quarantine that WAS released must not be resurrected by the replay, or the
// rebuilt control would be permanently sticky and a completed reconciliation
// could never re-open issuance.
func TestQuarantine_ReleaseSurvivesProcessRestart(t *testing.T) {
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
	released := quarantine.Released{
		ReleaseID:   "release-1",
		TenantID:    "tenant-a",
		AuthorityID: "vault",
		WitnessID:   evidence.Body.WitnessID,
		FromState:   quarantine.StateQuarantined,
		ToState:     quarantine.StateConsistent,
		Reason:      "reconciliation_completion",
		ReleasedAt:  1800000200,
	}
	if _, err := log.Append(ctx, releasedEvent(t, released)); err != nil {
		t.Fatalf("append release: %v", err)
	}

	after := replayIntoFreshManager(t, log)
	allowed, err := after.Admit(ctx, editionseam.AdmissionRequest{
		TenantID:       "tenant-a",
		Operation:      "issue",
		IdentityID:     "identity-1",
		IdempotencyKey: "idem-after-release",
		ObservedInputs: []editionseam.ObservedStateInput{{
			AuthorityID: "vault",
			RecordKey:   "tenant-a/x509_certificate/cert-a",
			Source:      "policy",
		}},
	})
	if err != nil {
		t.Fatalf("Admit after released replay: %v", err)
	}
	if !allowed.Allowed {
		t.Fatalf("replay resurrected a released quarantine: %+v", allowed)
	}
}

// TestQuarantine_AdmissionFailsClosedOnStateError proves the first half of the
// fail-closed requirement: a containment lookup that cannot answer must REFUSE,
// never fall through to AllowAdmission().
func TestQuarantine_AdmissionFailsClosedOnStateError(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		state quarantine.AdmissionState
	}{
		{"tenant gate cannot answer", unavailableState{}},
		{"authority lookup cannot answer", openButUnreadableState{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := quarantine.NewManager(quarantine.Options{
				Log:         &memoryLog{},
				Idempotency: idem.NewMemory(),
				Admission:   tc.state,
				Policy:      quarantine.ReferencePolicy("vault"),
				Now:         fixedNow,
			})
			decision, err := mgr.Admit(ctx, editionseam.AdmissionRequest{
				TenantID:       "tenant-a",
				Operation:      "issue",
				IdentityID:     "identity-1",
				IdempotencyKey: "idem-state-error",
				ObservedInputs: []editionseam.ObservedStateInput{{
					AuthorityID: "vault",
					RecordKey:   "tenant-a/x509_certificate/cert-a",
					Source:      "policy",
				}},
			})
			if decision.Allowed {
				t.Fatalf("unreadable containment state allowed issuance: %+v", decision)
			}
			if err == nil {
				t.Fatal("unreadable containment state did not surface a refusal error")
			}
			if !errors.Is(err, quarantine.ErrInvalidQuarantine) {
				t.Fatalf("error = %v, want an invalid-quarantine refusal", err)
			}
		})
	}
}

// TestQuarantine_AdmissionRefusesWhenDurableStateReportsOpen is the second half,
// and the one the earlier design of this seam failed. A durable AdmissionState
// wired through Options.Admission -- which is the entire reason the seam exists
// -- reports tenant-a quarantined on vault while the process-local MemoryState is
// empty, exactly the divergence a durable state produces after a restart. If the
// per-authority lookup is answered by the local map instead of the seam, it finds
// nothing, Admit falls through to AllowAdmission(), and containment silently
// fails open with no refusal event and no error.
func TestQuarantine_AdmissionRefusesWhenDurableStateReportsOpen(t *testing.T) {
	ctx := context.Background()
	log := &memoryLog{}
	mgr := quarantine.NewManager(quarantine.Options{
		Log:         log,
		Idempotency: idem.NewMemory(),
		Admission:   durableState{tenantID: "tenant-a", authorityID: "vault", witnessID: "witness-1"},
		Policy:      quarantine.ReferencePolicy("vault"),
		Now:         fixedNow,
	})
	if _, ok := mgr.State().Lookup("tenant-a", "vault"); ok {
		t.Fatal("precondition: the process-local state must be empty for this divergence test")
	}
	decision, err := mgr.Admit(ctx, editionseam.AdmissionRequest{
		TenantID:       "tenant-a",
		Operation:      "issue",
		IdentityID:     "identity-1",
		IdempotencyKey: "idem-durable-open",
		ObservedInputs: []editionseam.ObservedStateInput{{
			AuthorityID: "vault",
			RecordKey:   "tenant-a/x509_certificate/cert-a",
			Source:      "policy",
		}},
	})
	if err != nil {
		t.Fatalf("Admit against durable containment state: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("durable containment state reported OPEN and issuance was allowed anyway: %+v", decision)
	}
	if decision.RefusalID == "" || countEvents(log.events, quarantine.EventTypeRefused) != 1 {
		t.Fatalf("refusal was not recorded: decision = %+v events = %+v", decision, log.events)
	}

	// The pinned behaviour must not regress: an observed input from an authority
	// that is NOT quarantined is still allowed (quarantine_test.go pins this for
	// the in-process state; it must hold identically through the seam).
	allowed, err := mgr.Admit(ctx, editionseam.AdmissionRequest{
		TenantID:       "tenant-a",
		Operation:      "issue",
		IdentityID:     "identity-2",
		IdempotencyKey: "idem-durable-kms",
		ObservedInputs: []editionseam.ObservedStateInput{{
			AuthorityID: "kms",
			RecordKey:   "tenant-a/x509_certificate/cert-b",
			Source:      "policy",
		}},
	})
	if err != nil {
		t.Fatalf("Admit unrelated authority: %v", err)
	}
	if !allowed.Allowed {
		t.Fatalf("unrelated authority refused: %+v", allowed)
	}
}

// TestQuarantineStateProjection_TenantBinding pins AN-1 on the fold and the
// deliberate error policy: a cross-tenant payload is an integrity violation and
// is refused, while an unattributable or provenance-less event is skipped rather
// than bricking every tenant's boot.
func TestQuarantineStateProjection_TenantBinding(t *testing.T) {
	ctx := context.Background()
	base := quarantine.Entered{
		TenantID:     "tenant-a",
		AuthorityID:  "vault",
		WitnessID:    "witness-1",
		Reason:       "policy_violation",
		FromState:    quarantine.StateConsistent,
		ThroughState: quarantine.StateDiverged,
		ToState:      quarantine.StateQuarantined,
		EnteredAt:    1800000000,
	}
	for _, tc := range []struct {
		name       string
		event      eventspec.Event
		wantErr    bool
		wantFolded bool
	}{
		{
			name:       "envelope and payload agree",
			event:      enteredEvent(t, "tenant-a", base),
			wantFolded: true,
		},
		{
			name:    "payload names a different tenant than the envelope",
			event:   enteredEvent(t, "tenant-b", base),
			wantErr: true,
		},
		{
			name:  "no tenant on either side is unattributable, not fatal",
			event: enteredEvent(t, "", withTenant(base, "")),
		},
		{
			name:  "missing witness provenance is skipped, not fatal",
			event: enteredEvent(t, "tenant-a", withWitness(base, "")),
		},
		{
			name:    "undecodable payload is fatal",
			event:   eventspec.Event{Type: quarantine.EventTypeEntered, TenantID: "tenant-a", Data: []byte("{")},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := quarantine.NewMemoryState()
			proj := quarantine.NewStateProjection(state)
			err := proj.Apply(ctx, tc.event)
			if tc.wantErr != (err != nil) {
				t.Fatalf("Apply err = %v, wantErr = %v", err, tc.wantErr)
			}
			open, lookupErr := state.HasOpenTenantQuarantine(ctx, "tenant-a")
			if lookupErr != nil {
				t.Fatalf("HasOpenTenantQuarantine: %v", lookupErr)
			}
			if open != tc.wantFolded {
				t.Fatalf("tenant-a open = %v, want %v", open, tc.wantFolded)
			}
			if othersOpen, _ := state.HasOpenTenantQuarantine(ctx, "tenant-b"); othersOpen {
				t.Fatal("fold leaked a record into tenant-b")
			}
		})
	}
}

// replayIntoFreshManager is what a process restart does: a brand-new containment
// state, reset, then the whole log replayed through the projection from the
// beginning -- the same order projections.Projector.rebuildEventProjections uses.
func replayIntoFreshManager(t *testing.T, log *memoryLog) *quarantine.Manager {
	t.Helper()
	ctx := context.Background()
	state := quarantine.NewMemoryState()
	projection := quarantine.NewStateProjection(state)
	if err := projection.Reset(ctx); err != nil {
		t.Fatalf("projection reset: %v", err)
	}
	for _, ev := range log.events {
		if err := projection.Apply(ctx, ev); err != nil {
			t.Fatalf("projection apply %s: %v", ev.Type, err)
		}
	}
	return quarantine.NewManager(quarantine.Options{
		Log:         log,
		Idempotency: idem.NewMemory(),
		State:       state,
		Policy:      quarantine.ReferencePolicy("vault"),
		Now:         fixedNow,
	})
}

func enteredEvent(t *testing.T, envelopeTenantID string, payload quarantine.Entered) eventspec.Event {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal entered payload: %v", err)
	}
	return eventspec.Event{
		Type:          quarantine.EventTypeEntered,
		TenantID:      envelopeTenantID,
		SchemaVersion: eventspec.DefaultSchemaVersion,
		Data:          data,
	}
}

// releasedEvent builds the xrec.quarantine.released envelope exactly as
// Manager.append does in production: the envelope tenant is the payload tenant.
func releasedEvent(t *testing.T, payload quarantine.Released) eventspec.Event {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal released payload: %v", err)
	}
	return eventspec.Event{
		Type:          quarantine.EventTypeReleased,
		TenantID:      payload.TenantID,
		SchemaVersion: eventspec.DefaultSchemaVersion,
		Data:          data,
	}
}

func withTenant(in quarantine.Entered, tenantID string) quarantine.Entered {
	in.TenantID = tenantID
	return in
}

func withWitness(in quarantine.Entered, witnessID string) quarantine.Entered {
	in.WitnessID = witnessID
	return in
}

// unavailableState cannot answer the tenant gate at all.
type unavailableState struct{}

func (unavailableState) HasOpenTenantQuarantine(context.Context, string) (bool, error) {
	return false, errors.New("containment substrate unavailable")
}

func (unavailableState) LookupOpenQuarantine(context.Context, string, string) (quarantine.Record, bool, error) {
	return quarantine.Record{}, false, errors.New("containment substrate unavailable")
}

// openButUnreadableState answers the gate but fails the per-authority lookup --
// the branch that previously degraded to "no quarantined authority" and allowed.
type openButUnreadableState struct{}

func (openButUnreadableState) HasOpenTenantQuarantine(context.Context, string) (bool, error) {
	return true, nil
}

func (openButUnreadableState) LookupOpenQuarantine(context.Context, string, string) (quarantine.Record, bool, error) {
	return quarantine.Record{}, false, errors.New("containment record lookup failed")
}

// durableState stands in for a containment state that outlives the process --
// the thing Options.Admission exists to allow -- and is deliberately NOT the
// Manager's process-local MemoryState.
type durableState struct {
	tenantID    string
	authorityID string
	witnessID   string
}

func (d durableState) HasOpenTenantQuarantine(_ context.Context, tenantID string) (bool, error) {
	return tenantID == d.tenantID, nil
}

func (d durableState) LookupOpenQuarantine(_ context.Context, tenantID, authorityID string) (quarantine.Record, bool, error) {
	if tenantID != d.tenantID || authorityID != d.authorityID {
		return quarantine.Record{}, false, nil
	}
	return quarantine.Record{
		TenantID:    d.tenantID,
		AuthorityID: d.authorityID,
		WitnessID:   d.witnessID,
		State:       quarantine.StateQuarantined,
		Open:        true,
		EnteredAt:   1800000000,
	}, true, nil
}
