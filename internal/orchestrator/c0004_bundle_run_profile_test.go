// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
)

func TestC0004RetainedBundleRunOwnerProfileVoteHasNoQuorumPower(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	mustRegisterTenant(t, s, tenantA)
	o := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	creator := events.ContextWithActor(ctx, events.Actor{Subject: "bundle-run:c0004-owner"})
	spec := mustProfileSpec(t, profile.CertificateProfile{
		Name: "c0004-governed", RequiresApproval: true, MaxValidity: profile.Duration(24 * time.Hour),
	})
	_, err := o.CreateProfile(creator, tenantA, "c0004-governed", spec)
	var pending *orchestrator.ProfileEditPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("governed profile was not parked: %v", err)
	}
	t.Cleanup(func() {
		if err := s.WithTenant(context.Background(), tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(),
				`DELETE FROM profile_edit_approvals WHERE tenant_id=$1 AND id=$2`, tenantA, pending.Request.ID)
			return err
		}); err != nil {
			t.Errorf("clean exact C0004 profile approval fixture: %v", err)
		}
	})
	// A retained pre-fix vote remains auditable, but loses quorum power.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyProfileEditApprovalApprovedTx(ctx, tx, tenantA, pending.Request.ID, "c0004-owner", time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	retained, err := o.GetProfileEditApproval(ctx, tenantA, pending.Request.ID)
	if err != nil || retained.State != "awaiting_approval" || len(retained.Approvals) != 1 {
		t.Fatalf("retained owner vote counted toward profile quorum: %+v, err=%v", retained, err)
	}
	owner := events.ContextWithActor(ctx, events.Actor{Subject: "c0004-owner"})
	if _, err := o.ApproveProfileEdit(owner, tenantA, pending.Request.ID, "c0004-owner"); !errors.Is(err, orchestrator.ErrProfileEditSelfApproval) {
		t.Fatalf("owner approved their bundle run's profile: %v", err)
	}
}
