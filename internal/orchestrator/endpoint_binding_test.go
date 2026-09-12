// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestEndpointBindingAuthoritySurvivesReplayAndRefusesRepurposing(t *testing.T) {
	ctx := t.Context()
	st := newStore(t)
	log := openLog(t)
	outbox := orchestrator.NewOutbox(st)
	orch := orchestrator.NewOrchestrator(log, st, outbox)
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "endpoint owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "claimed.example.test", OwnerID: owner.ID,
		Attributes: json.RawMessage(`{"discovery_source":"local-scan"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := orch.UpsertDeploymentTarget(ctx, tenantA, store.DeploymentTarget{
		Name: "owned-nginx", Type: "nginx", Config: json.RawMessage(`{"executor":"agent"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer := store.IdentityEndpointIssuer{OwnerID: owner.ID, Source: "external", ID: "customer-ca", Name: "Customer CA", PreviewFingerprint: strings.Repeat("a", 64)}
	assertRefused := func(candidate store.IdentityEndpointIssuer, tenant string) {
		t.Helper()
		before, err := log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = orch.BindIdentityEndpoint(ctx, tenant, identity.ID, target, candidate)
		if err == nil {
			t.Fatal("unsafe enrollment succeeded")
		}
		if tenant == tenantA && !errors.Is(err, store.ErrIdentityEnrollmentConflict) {
			t.Fatal(err)
		}
		after, err := log.LastSequence(ctx)
		if err != nil || before != after {
			t.Fatalf("refusal appended an event: before=%d after=%d err=%v", before, after, err)
		}
	}
	otherOwner := issuer
	otherOwner.OwnerID = "another-owner"
	assertRefused(otherOwner, tenantA)
	assertRefused(issuer, tenantB)
	_, reviewedVersion, err := st.IdentityApprovalTarget(ctx, tenantA, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	wrongVersion := reviewedVersion + 1
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.BindIdentityEndpointAtVersion(ctx, tenantA, identity.ID, target, issuer, &wrongVersion); !errors.Is(err, store.ErrIdentityEnrollmentConflict) {
		t.Fatalf("stale review accepted: %v", err)
	}
	after, err := log.LastSequence(ctx)
	if err != nil || before != after {
		t.Fatalf("stale review appended work: %d -> %d %v", before, after, err)
	}
	if _, err := orch.BindIdentityEndpointAtVersion(ctx, tenantA, identity.ID, target, issuer, &reviewedVersion); err != nil {
		t.Fatal(err)
	}
	before, err = log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.BindIdentityEndpointAtVersion(ctx, tenantA, identity.ID, target, issuer, &reviewedVersion); err != nil {
		t.Fatalf("lost bind reply cannot resume: %v", err)
	}
	after, err = log.LastSequence(ctx)
	if err != nil || before != after {
		t.Fatalf("bind replay changed the approval revision: %d -> %d %v", before, after, err)
	}

	assertBinding := func() {
		t.Helper()
		got, err := st.GetIdentity(ctx, tenantA, identity.ID)
		if err != nil {
			t.Fatal(err)
		}
		var attrs map[string]string
		if err := json.Unmarshal(got.Attributes, &attrs); err != nil {
			t.Fatal(err)
		}
		for key, want := range map[string]string{
			"discovery_source": "local-scan", "issuing_authority_source": "external",
			"issuing_authority_id": "customer-ca", "issuing_authority_name": "Customer CA",
			"deployment_target_id": target.ID, "endpoint_preview_sha256": issuer.PreviewFingerprint,
		} {
			if attrs[key] != want {
				t.Fatalf("%s=%q, want %q", key, attrs[key], want)
			}
		}
	}
	assertBinding()
	otherIssuer := issuer
	otherIssuer.Source, otherIssuer.ID = "platform", "trstctl-issuing-ca"
	assertRefused(otherIssuer, tenantA)
	if pending, err := outbox.Pending(ctx, tenantA); err != nil || len(pending) != 0 {
		t.Fatalf("binding triggered external work: count=%d err=%v", len(pending), err)
	}
	if err := orch.Transition(ctx, tenantA, identity.ID, orchestrator.StateIssued, "issue through reviewed CA"); err != nil {
		t.Fatal(err)
	}
	assertRefused(issuer, tenantA)
	// Live commands apply inline before the background checkpoint advances.
	// Catch-up must replay the accepted binding over the advanced lifecycle.
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch up issued endpoint binding: %v", err)
	}
	assertBinding()
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild endpoint binding: %v", err)
	}
	assertBinding()
}
