// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/approval"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
)

// OPP-R09: a parked profile create/edit survives the process that parked it.
// The request is an event; its projection carries the state, so a second
// orchestrator over the same store (a restarted plane, or another replica)
// lists it, refuses the requester's self-approval, records a reviewer's
// approval and applies the queued spec. An identical approval afterwards is
// absorbed, and the closed request names the version it produced.
func TestParkedProfileEditApprovalSurvivesARestart(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	mustRegisterTenant(t, s, tenantA)
	first := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	aliceCtx := events.ContextWithActor(ctx, events.Actor{Subject: "alice"})
	bobCtx := events.ContextWithActor(ctx, events.Actor{Subject: "bob"})
	spec := mustProfileSpec(t, profile.CertificateProfile{Name: "governed", RequiresApproval: true, MaxValidity: profile.Duration(24 * time.Hour)})
	_, err := first.CreateProfile(aliceCtx, tenantA, "governed", spec)
	var pending *orchestrator.ProfileEditPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("governed create = %v, want ProfileEditPendingError", err)
	}

	// "Restart": a fresh orchestrator over the same store and log knows nothing
	// in memory; everything it needs is in the projection.
	second := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	listed, err := second.ListProfileEditApprovals(ctx, tenantA)
	if err != nil || len(listed) != 1 || listed[0].ID != pending.Request.ID || listed[0].State != string(approval.StateAwaitingApproval) {
		t.Fatalf("after restart: list = %+v err=%v, want the parked request awaiting approval", listed, err)
	}
	if _, err := second.ApproveProfileEdit(aliceCtx, tenantA, pending.Request.ID, "alice"); !errors.Is(err, orchestrator.ErrProfileEditSelfApproval) {
		t.Fatalf("self-approval after restart = %v, want dual-control refusal", err)
	}
	applied, err := second.ApproveProfileEdit(bobCtx, tenantA, pending.Request.ID, "bob")
	if err != nil {
		t.Fatalf("approve after restart: %v", err)
	}
	if applied.State != string(approval.StateIssued) || applied.ProfileID == "" || len(applied.Approvals) != 1 {
		t.Fatalf("approved request = %+v, want issued with one decision and a profile id", applied)
	}
	active, err := s.GetActiveProfile(ctx, tenantA, "governed")
	if err != nil || active.ID != applied.ProfileID || active.Version != 1 {
		t.Fatalf("active profile after approval = %+v err=%v, want version 1 with id %s", active, err, applied.ProfileID)
	}
	// An identical approval is absorbed: one decision, still the same version.
	again, err := second.ApproveProfileEdit(bobCtx, tenantA, pending.Request.ID, "bob")
	if err != nil || len(again.Approvals) != 1 || again.ProfileID != applied.ProfileID {
		t.Fatalf("identical approval = %+v err=%v, want absorbed", again, err)
	}
	if _, err := second.GetProfileEditApproval(ctx, tenantA, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, orchestrator.ErrProfileEditApprovalUnknown) {
		t.Fatalf("unknown id = %v, want ErrProfileEditApprovalUnknown", err)
	}
	// Replaying the parked-request event a second time (the durable tail behind
	// the inline apply) changes nothing.
	proj := projections.New(s)
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		if e.Type == projections.EventProfileEditApprovalRequested || e.Type == projections.EventProfileEditApprovalApproved {
			return proj.Apply(ctx, e)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay of the approval events: %v", err)
	}
	final, err := second.GetProfileEditApproval(ctx, tenantA, pending.Request.ID)
	if err != nil || final.State != string(approval.StateIssued) || len(final.Approvals) != 1 {
		t.Fatalf("after replay = %+v err=%v, want still issued with one decision", final, err)
	}
}
