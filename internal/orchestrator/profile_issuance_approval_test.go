package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

func TestProfileApprovalRequirementResolvesIdentityBoundProfile(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	mustRegisterTenant(t, st, tenantA)
	orch := orchestrator.NewOrchestrator(openLog(t), st, orchestrator.NewOutbox(st))
	aliceCtx := events.ContextWithActor(ctx, events.Actor{Subject: "alice"})
	bobCtx := events.ContextWithActor(ctx, events.Actor{Subject: "bob"})

	normalSpec := mustProfileSpec(t, profile.CertificateProfile{
		Name:        "standard",
		MaxValidity: profile.Duration(24 * time.Hour),
	})
	if _, err := orch.CreateProfile(aliceCtx, tenantA, "standard", normalSpec); err != nil {
		t.Fatalf("CreateProfile standard: %v", err)
	}

	gatedSpec := mustProfileSpec(t, profile.CertificateProfile{
		Name:             "prod",
		RequiresApproval: true,
		MaxValidity:      profile.Duration(24 * time.Hour),
	})
	_, err := orch.CreateProfile(aliceCtx, tenantA, "prod", gatedSpec)
	pending := profileEditPending(t, err)
	if _, err := orch.ApproveProfileEdit(bobCtx, tenantA, pending.Request.ID, "bob"); err != nil {
		t.Fatalf("ApproveProfileEdit prod: %v", err)
	}

	owner, err := orch.CreateOwner(aliceCtx, tenantA, "team", "payments", "payments@example.test")
	if err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	normalIdentity, err := orch.CreateIdentity(aliceCtx, tenantA, store.Identity{
		Kind:       store.KindX509Certificate,
		Name:       "standard-cert",
		OwnerID:    owner.ID,
		Attributes: json.RawMessage(`{"profile_name":"standard"}`),
	})
	if err != nil {
		t.Fatalf("CreateIdentity standard: %v", err)
	}
	gatedIdentity, err := orch.CreateIdentity(aliceCtx, tenantA, store.Identity{
		Kind:       store.KindX509Certificate,
		Name:       "prod-cert",
		OwnerID:    owner.ID,
		Attributes: json.RawMessage(`{"profile_name":"prod"}`),
	})
	if err != nil {
		t.Fatalf("CreateIdentity prod: %v", err)
	}

	normal, err := orch.ProfileApprovalRequirement(ctx, tenantA, normalIdentity.ID)
	if err != nil {
		t.Fatalf("ProfileApprovalRequirement standard: %v", err)
	}
	if normal.ProfileName != "standard" || normal.RequiresApproval {
		t.Fatalf("standard requirement = %+v, want standard without approval", normal)
	}
	gated, err := orch.ProfileApprovalRequirement(ctx, tenantA, gatedIdentity.ID)
	if err != nil {
		t.Fatalf("ProfileApprovalRequirement prod: %v", err)
	}
	if gated.ProfileName != "prod" || !gated.RequiresApproval {
		t.Fatalf("prod requirement = %+v, want prod requiring approval", gated)
	}
}

func profileEditPending(t *testing.T, err error) *orchestrator.ProfileEditPendingError {
	t.Helper()
	var pending *orchestrator.ProfileEditPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("CreateProfile err = %v, want ProfileEditPendingError", err)
	}
	return pending
}
