// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestEndpointReplacementKeepsOriginalAndResumesExactlyOneSuccessor(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "same business owner", "")
	if err != nil {
		t.Fatal(err)
	}
	target, err := orch.UpsertDeploymentTarget(ctx, tenantA, store.DeploymentTarget{
		Name: "replacement-nginx", Type: "nginx", Config: json.RawMessage(`{"executor":"agent"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	original, err := orch.CreateIdentity(ctx, tenantA, store.Identity{Kind: store.KindX509Certificate,
		Name: "replace.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	issuer := store.IdentityEndpointIssuer{OwnerID: owner.ID, Source: "external", ID: "customer-ca", Name: "Customer CA", PreviewFingerprint: strings.Repeat("a", 64)}
	if _, err := orch.BindIdentityEndpoint(ctx, tenantA, original.ID, target, issuer); err != nil {
		t.Fatal(err)
	}
	// Seed completed lifecycle effects; the replacement command itself must
	// neither sign a certificate nor invent a deployment receipt.
	if err := orch.Transition(ctx, tenantA, original.ID, orchestrator.StateIssued, "fixture issued"); err != nil {
		t.Fatal(err)
	}
	if err := orch.Transition(ctx, tenantA, original.ID, orchestrator.StateDeployed, "fixture deployed"); err != nil {
		t.Fatal(err)
	}
	if _, err := orchestrator.NewOutbox(st).Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { return nil })); err != nil {
		t.Fatal(err)
	}
	original, version, err := st.IdentityApprovalTarget(ctx, tenantA, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertRefused := func(source store.Identity, sourceVersion uint64, selected store.DeploymentTarget) {
		t.Helper()
		before, err := log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := orch.EnsureEndpointReplacement(ctx, tenantA, source, sourceVersion, selected, issuer); err == nil {
			t.Fatal("unsafe replacement accepted")
		}
		after, err := log.LastSequence(ctx)
		if err != nil || before != after {
			t.Fatalf("refusal appended event: %d -> %d: %v", before, after, err)
		}
	}
	assertRefused(original, version-1, target)
	changed := original
	changed.Name = "another.example.test"
	assertRefused(changed, version, target)
	wrongTarget := target
	wrongTarget.ID = "11111111-1111-4111-8111-111111111111"
	assertRefused(original, version, wrongTarget)

	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := orch.EnsureEndpointReplacement(ctx, tenantA, original, version, target, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ID == original.ID || replacement.Name != original.Name || replacement.OwnerID != owner.ID || replacement.Status != "requested" {
		t.Fatalf("replacement did not preserve the DNS name/owner in a separate identity: %+v", replacement)
	}
	var attrs map[string]string
	if err := json.Unmarshal(replacement.Attributes, &attrs); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"endpoint_replaces_identity_id": original.ID, "deployment_target_id": target.ID,
		"issuing_authority_id": issuer.ID, "issuing_authority_source": "external", "endpoint_preview_sha256": issuer.PreviewFingerprint} {
		if attrs[key] != want {
			t.Fatalf("%s=%q, want %q", key, attrs[key], want)
		}
	}
	retry, err := orch.EnsureEndpointReplacement(ctx, tenantA, original, version, target, issuer)
	if err != nil || retry.ID != replacement.ID {
		t.Fatalf("retry created another replacement: %+v %v", retry, err)
	}
	after, err := log.LastSequence(ctx)
	if err != nil || after != before+1 {
		t.Fatalf("replacement/retry event count: %d -> %d: %v", before, after, err)
	}
	got, gotVersion, err := st.IdentityApprovalTarget(ctx, tenantA, original.ID)
	if err != nil || got.Status != "deployed" || gotVersion != version {
		t.Fatalf("original changed or revoked early: %+v %d %v", got, gotVersion, err)
	}
	if pending, err := orchestrator.NewOutbox(st).Pending(ctx, tenantA); err != nil || len(pending) != 0 {
		t.Fatalf("replacement preparation performed external work: %+v %v", pending, err)
	}
	// A sibling must not compete for the listener while replacement is active.
	if err := orch.TransitionWithIdempotency(ctx, tenantA, replacement.ID, orchestrator.StateIssued, "reviewed replacement", "replacement-issue"); err != nil {
		t.Fatal(err)
	}
	issuer.PreviewFingerprint = strings.Repeat("b", 64)
	assertRefused(original, version, target)
	if err := orch.Transition(ctx, tenantA, original.ID, orchestrator.StateRenewing, "old scheduler races replacement"); err == nil {
		t.Fatal("original renewal can overwrite its replacement")
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	replayed, err := st.GetIdentity(ctx, tenantA, replacement.ID)
	if err != nil || string(replayed.Attributes) != string(replacement.Attributes) {
		t.Fatalf("replacement lost its exact binding on replay: %+v %v", replayed, err)
	}
}

func TestUnissuedEndpointReplacementDoesNotPauseOriginalAndCannotIssueAfterDrift(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	ob := orchestrator.NewOutbox(st)
	orch := orchestrator.NewOrchestrator(log, st, ob)
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "pending replacement owner", "")
	if err != nil {
		t.Fatal(err)
	}
	target, err := orch.UpsertDeploymentTarget(ctx, tenantA, store.DeploymentTarget{Name: "pending-target", Type: "nginx", Config: json.RawMessage(`{"executor":"agent"}`)})
	if err != nil {
		t.Fatal(err)
	}
	original, err := orch.CreateIdentity(ctx, tenantA, store.Identity{Kind: store.KindX509Certificate, Name: "pending.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	issuer := store.IdentityEndpointIssuer{OwnerID: owner.ID, Source: "external", ID: "customer-ca", Name: "Customer CA", PreviewFingerprint: strings.Repeat("c", 64)}
	if _, err := orch.BindIdentityEndpoint(ctx, tenantA, original.ID, target, issuer); err != nil {
		t.Fatal(err)
	}
	if err := orch.Transition(ctx, tenantA, original.ID, orchestrator.StateIssued, "fixture issued"); err != nil {
		t.Fatal(err)
	}
	if err := orch.Transition(ctx, tenantA, original.ID, orchestrator.StateDeployed, "fixture deployed"); err != nil {
		t.Fatal(err)
	}
	if _, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { return nil })); err != nil {
		t.Fatal(err)
	}
	original, version, err := st.IdentityApprovalTarget(ctx, tenantA, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.EnsureEndpointReplacement(ctx, tenantB, original, version, target, issuer); err == nil {
		t.Fatal("cross-tenant original accepted")
	}
	replacement, err := orch.EnsureEndpointReplacement(ctx, tenantA, original, version, target, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err := orch.Transition(ctx, tenantA, original.ID, orchestrator.StateRenewing, "valid certificate still renews before successor issuance"); err != nil {
		t.Fatalf("unissued replacement paused the original: %v", err)
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := orch.TransitionWithIdempotency(ctx, tenantA, replacement.ID, orchestrator.StateIssued, "stale replacement", "stale-replacement-issue"); err == nil {
		t.Fatal("replacement issued after original started a competing renewal")
	}
	after, err := log.LastSequence(ctx)
	if err != nil || after != before {
		t.Fatalf("stale replacement published work: %d -> %d %v", before, after, err)
	}
}
