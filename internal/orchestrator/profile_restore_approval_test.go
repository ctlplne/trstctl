// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

func TestProfileRestorePreservesDualControlAndFailsClosedAfterApprovalDrift(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	// A unique tenant keeps this real-PostgreSQL test isolated from any worker a
	// preceding integration test is still draining during the full race run.
	tenantID := uuid.NewString()
	mustRegisterTenant(t, st, tenantID)
	orch := orchestrator.NewOrchestrator(openLog(t), st, orchestrator.NewOutbox(st))
	aliceCtx := events.ContextWithActor(ctx, events.Actor{Subject: "alice"})
	bobCtx := events.ContextWithActor(ctx, events.Actor{Subject: "bob"})

	knownGood := mustProfileSpec(t, profile.CertificateProfile{
		Name: "web", MaxValidity: profile.Duration(24 * time.Hour),
	})
	if _, err := orch.CreateProfile(aliceCtx, tenantID, "web", knownGood); err != nil {
		t.Fatalf("create known-good profile: %v", err)
	}
	gated := mustProfileSpec(t, profile.CertificateProfile{
		Name: "web", RequiresApproval: true, MaxValidity: profile.Duration(time.Hour),
	})
	_, err := orch.CreateProfile(aliceCtx, tenantID, "web", gated)
	var gatedCreate *orchestrator.ProfileEditPendingError
	if !errors.As(err, &gatedCreate) {
		t.Fatalf("create gated v2 err = %v, want approval", err)
	}
	if _, err := orch.ApproveProfileEdit(bobCtx, tenantID, gatedCreate.Request.ID, "bob"); err != nil {
		t.Fatalf("approve gated v2: %v", err)
	}

	_, err = orch.RestoreProfileVersion(aliceCtx, tenantID, "web", 1, 2, "Recover the known-good issuance rule")
	var restore *orchestrator.ProfileEditPendingError
	if !errors.As(err, &restore) {
		t.Fatalf("restore over gated active profile err = %v, want approval", err)
	}
	if _, err := orch.ApproveProfileEdit(aliceCtx, tenantID, restore.Request.ID, "alice"); err == nil {
		t.Fatal("requester self-approved a profile recovery")
	}
	if _, err := orch.ApproveProfileEdit(bobCtx, tenantID, restore.Request.ID, "bob"); err != nil {
		t.Fatalf("approve profile recovery: %v", err)
	}
	active, err := st.GetActiveProfile(ctx, tenantID, "web")
	if err != nil || active.Version != 3 || store.ProfileSpecDigest(active.Spec) != store.ProfileSpecDigest(knownGood) {
		t.Fatalf("active after approved recovery = (%+v, %v), want known-good v3", active, err)
	}

	_, err = orch.RestoreProfileVersion(aliceCtx, tenantID, "web", 2, 3, "Reapply the stricter gated rule")
	var staleRestore *orchestrator.ProfileEditPendingError
	if !errors.As(err, &staleRestore) {
		t.Fatalf("second gated restore err = %v, want approval", err)
	}
	newer := mustProfileSpec(t, profile.CertificateProfile{
		Name: "web", MaxValidity: profile.Duration(12 * time.Hour),
	})
	if _, err := orch.CreateProfile(aliceCtx, tenantID, "web", newer); err != nil {
		t.Fatalf("create concurrent v4: %v", err)
	}
	if _, err := orch.ApproveProfileEdit(bobCtx, tenantID, staleRestore.Request.ID, "bob"); !errors.Is(err, orchestrator.ErrProfileRestoreStale) {
		t.Fatalf("approve stale recovery err = %v, want ErrProfileRestoreStale", err)
	}
	active, err = st.GetActiveProfile(ctx, tenantID, "web")
	if err != nil || active.Version != 4 || store.ProfileSpecDigest(active.Spec) != store.ProfileSpecDigest(newer) {
		t.Fatalf("active after stale approval = (%+v, %v), want untouched v4", active, err)
	}
}
