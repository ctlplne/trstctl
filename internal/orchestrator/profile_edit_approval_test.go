package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/approval"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

func TestProfileEditRequiresApprovalAndDualControl(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	mustRegisterTenant(t, st, tenantA)
	orch := orchestrator.NewOrchestrator(openLog(t), st, orchestrator.NewOutbox(st))

	aliceCtx := events.ContextWithActor(ctx, events.Actor{Subject: "alice"})
	directSpec := mustProfileSpec(t, profile.CertificateProfile{
		Name:        "dev",
		MaxValidity: profile.Duration(time.Hour),
	})
	direct, err := orch.CreateProfile(aliceCtx, tenantA, "dev", directSpec)
	if err != nil {
		t.Fatalf("CreateProfile non-gated: %v", err)
	}
	if direct.Version != 1 {
		t.Fatalf("direct version = %d, want 1", direct.Version)
	}

	gatedSpec := mustProfileSpec(t, profile.CertificateProfile{
		Name:             "web",
		RequiresApproval: true,
		MaxValidity:      profile.Duration(24 * time.Hour),
	})
	_, err = orch.CreateProfile(aliceCtx, tenantA, "web", gatedSpec)
	var pending *orchestrator.ProfileEditPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("CreateProfile gated err = %v, want ProfileEditPendingError", err)
	}
	if pending.Request.Kind != approval.KindProfileEdit || pending.Request.State != approval.StateAwaitingApproval {
		t.Fatalf("pending request = %+v, want profile_edit awaiting approval", pending.Request)
	}
	if pending.Request.Requester != "alice" {
		t.Fatalf("requester = %q, want alice", pending.Request.Requester)
	}
	if _, err := st.GetActiveProfile(ctx, tenantA, "web"); !store.IsNotFound(err) {
		t.Fatalf("active gated profile err = %v, want not found before approval", err)
	}

	if _, err := orch.ApproveProfileEdit(aliceCtx, tenantA, pending.Request.ID, "alice"); err == nil {
		t.Fatal("self-approval succeeded, want dual-control rejection")
	}
	if _, err := st.GetActiveProfile(ctx, tenantA, "web"); !store.IsNotFound(err) {
		t.Fatalf("active gated profile after self-approval err = %v, want not found", err)
	}

	bobCtx := events.ContextWithActor(ctx, events.Actor{Subject: "bob"})
	applied, err := orch.ApproveProfileEdit(bobCtx, tenantA, pending.Request.ID, "bob")
	if err != nil {
		t.Fatalf("ApproveProfileEdit by non-requester: %v", err)
	}
	if applied.State != approval.StateIssued {
		t.Fatalf("approved state = %q, want issued", applied.State)
	}
	active, err := st.GetActiveProfile(ctx, tenantA, "web")
	if err != nil {
		t.Fatalf("GetActiveProfile after approval: %v", err)
	}
	var activeProfile profile.CertificateProfile
	if err := json.Unmarshal(active.Spec, &activeProfile); err != nil {
		t.Fatal(err)
	}
	if !activeProfile.RequiresApproval || active.Version != 1 {
		t.Fatalf("active profile = %+v version %d, want requires_approval version 1", activeProfile, active.Version)
	}

	relaxedSpec := mustProfileSpec(t, profile.CertificateProfile{
		Name:             "web",
		RequiresApproval: false,
		MaxValidity:      profile.Duration(48 * time.Hour),
	})
	_, err = orch.CreateProfile(aliceCtx, tenantA, "web", relaxedSpec)
	var relaxation *orchestrator.ProfileEditPendingError
	if !errors.As(err, &relaxation) {
		t.Fatalf("relaxing approval-tier profile err = %v, want ProfileEditPendingError", err)
	}
	active, err = st.GetActiveProfile(ctx, tenantA, "web")
	if err != nil {
		t.Fatalf("GetActiveProfile after queued relaxation: %v", err)
	}
	if active.Version != 1 {
		t.Fatalf("active version after queued relaxation = %d, want still 1", active.Version)
	}
	if _, err := orch.ApproveProfileEdit(bobCtx, tenantA, relaxation.Request.ID, "bob"); err != nil {
		t.Fatalf("ApproveProfileEdit relaxation: %v", err)
	}
	active, err = st.GetActiveProfile(ctx, tenantA, "web")
	if err != nil {
		t.Fatalf("GetActiveProfile after relaxation approval: %v", err)
	}
	if active.Version != 2 {
		t.Fatalf("active version after relaxation approval = %d, want 2", active.Version)
	}
	activeProfile = profile.CertificateProfile{}
	if err := json.Unmarshal(active.Spec, &activeProfile); err != nil {
		t.Fatal(err)
	}
	if activeProfile.RequiresApproval {
		t.Fatalf("relaxed profile still requires approval: %+v", activeProfile)
	}
}

func mustProfileSpec(t *testing.T, p profile.CertificateProfile) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
