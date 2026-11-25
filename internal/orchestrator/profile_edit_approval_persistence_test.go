// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/approval"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestParkedProfileEditRejectsHistoricalDelegatedMinter(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	mustRegisterTenant(t, s, tenantA)
	if _, err := s.CreateAPIToken(ctx, store.APITokenRecord{TenantID: tenantA, TokenHash: privacy.SubjectRef(tenantA, "cr972-profile-holder"), Subject: "cr972-profile-service", MintedBy: "cr972-profile-minter"}); err != nil {
		t.Fatal(err)
	}
	o := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	creator := events.ContextWithActor(ctx, events.Actor{Subject: "cr972-profile-service"})
	spec := mustProfileSpec(t, profile.CertificateProfile{Name: "cr972-profile", RequiresApproval: true, MaxValidity: profile.Duration(24 * time.Hour)})
	_, err := o.CreateProfile(creator, tenantA, "cr972-profile", spec)
	var pending *orchestrator.ProfileEditPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("park historical profile request: %v", err)
	}
	t.Cleanup(func() {
		if err := s.WithTenant(context.Background(), tenantA, func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), `DELETE FROM profile_edit_approvals WHERE tenant_id=$1 AND id=$2`, tenantA, pending.Request.ID); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `DELETE FROM certificate_profiles WHERE tenant_id=$1 AND name=$2`, tenantA, "cr972-profile"); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `DELETE FROM api_tokens WHERE tenant_id=$1 AND token_hash=$2`, tenantA, privacy.SubjectRef(tenantA, "cr972-profile-holder"))
			return err
		}); err != nil {
			t.Errorf("clean exact CR-972 test rows: %v", err)
		}
	})
	minter := events.ContextWithActor(ctx, events.Actor{Subject: "cr972-profile-minter"})
	if _, err := o.ApproveProfileEdit(minter, tenantA, pending.Request.ID, "cr972-profile-minter"); !errors.Is(err, orchestrator.ErrProfileEditSelfApproval) {
		t.Fatalf("token minter approved a parked request: %v", err)
	}
	independent := events.ContextWithActor(ctx, events.Actor{Subject: "cr972-independent"})
	approved, err := o.ApproveProfileEdit(independent, tenantA, pending.Request.ID, "cr972-independent")
	if err != nil {
		t.Fatalf("independent approval refused: %v", err)
	}
	for n := 2; approved.State == string(approval.StateAwaitingApproval) && n <= pending.Request.RequiredApprovals; n++ {
		reviewer := fmt.Sprintf("cr972-independent-%d", n)
		approved, err = o.ApproveProfileEdit(events.ContextWithActor(ctx, events.Actor{Subject: reviewer}), tenantA, pending.Request.ID, reviewer)
		if err != nil {
			t.Fatalf("independent reviewer %d refused: %v", n, err)
		}
	}
	if approved.State != string(approval.StateIssued) {
		t.Fatalf("test request remained pending and could pollute other tests: %s", approved.State)
	}
}

func TestRetainedDelegatedMinterProfileDecisionCannotCompleteQuorum(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	mustRegisterTenant(t, s, tenantA)
	if _, err := s.CreateAPIToken(ctx, store.APITokenRecord{TenantID: tenantA, TokenHash: privacy.SubjectRef(tenantA, "cr972-retained-profile-holder"), Subject: "cr972-retained-profile-service", MintedBy: "cr972-retained-profile-minter"}); err != nil {
		t.Fatal(err)
	}
	o := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	creator := events.ContextWithActor(ctx, events.Actor{Subject: "cr972-retained-profile-service"})
	spec := mustProfileSpec(t, profile.CertificateProfile{Name: "cr972-retained-profile", RequiresApproval: true, MaxValidity: profile.Duration(24 * time.Hour)})
	_, err := o.CreateProfile(creator, tenantA, "cr972-retained-profile", spec)
	var pending *orchestrator.ProfileEditPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("park retained profile request: %v", err)
	}
	t.Cleanup(func() {
		if err := s.WithTenant(context.Background(), tenantA, func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), `DELETE FROM profile_edit_approvals WHERE tenant_id=$1 AND id=$2`, tenantA, pending.Request.ID); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `DELETE FROM certificate_profiles WHERE tenant_id=$1 AND name=$2`, tenantA, "cr972-retained-profile"); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `DELETE FROM api_tokens WHERE tenant_id=$1 AND token_hash=$2`, tenantA, privacy.SubjectRef(tenantA, "cr972-retained-profile-holder"))
			return err
		}); err != nil {
			t.Errorf("clean exact CR-972 retained profile rows: %v", err)
		}
	})
	// Model a two-person historical request with the minter's old decision
	// already projected. It remains in the audit record after the fix.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE profile_edit_approvals SET required_approvals=2 WHERE tenant_id=$1 AND id=$2`, tenantA, pending.Request.ID); err != nil {
			return err
		}
		return s.ApplyProfileEditApprovalApprovedTx(ctx, tx, tenantA, pending.Request.ID, "cr972-retained-profile-minter", time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	retained, err := o.GetProfileEditApproval(ctx, tenantA, pending.Request.ID)
	if err != nil || retained.State != string(approval.StateAwaitingApproval) || len(retained.Approvals) != 1 {
		t.Fatalf("retained minter vote should remain auditable but not appear approved: state=%+v err=%v", retained, err)
	}
	reviewer := events.ContextWithActor(ctx, events.Actor{Subject: "cr972-retained-profile-reviewer"})
	state, err := o.ApproveProfileEdit(reviewer, tenantA, pending.Request.ID, "cr972-retained-profile-reviewer")
	if err != nil {
		t.Fatal(err)
	}
	if state.State == string(approval.StateIssued) {
		t.Fatalf("one independent vote and a retained minter vote issued the profile: %+v", state)
	}
	if len(state.Approvals) != 2 {
		t.Fatalf("historical vote disappeared from audit: %+v", state)
	}
	second := events.ContextWithActor(ctx, events.Actor{Subject: "cr972-retained-profile-reviewer-2"})
	state, err = o.ApproveProfileEdit(second, tenantA, pending.Request.ID, "cr972-retained-profile-reviewer-2")
	if err != nil || state.State != string(approval.StateIssued) {
		t.Fatalf("two independent votes did not issue profile: state=%+v err=%v", state, err)
	}
}

// OPP-R09: a parked profile create/edit survives the process that parked it.
// The request is an event; its projection carries the state, so a second
// orchestrator over the same store (a restarted plane, or another replica)
// lists it, refuses the requester's self-approval, records a reviewer's
// approval and applies the queued spec. An identical approval afterward is
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
