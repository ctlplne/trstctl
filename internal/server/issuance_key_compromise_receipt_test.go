// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// The dispatcher, rather than the lifecycle transition, must append the CA
// completion receipt. Its indexed event survives delivered-outbox retention GC.
func TestCompoundKeyCompromiseDispatcherRetainsExactCAOutcome(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "compound revocation owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "compound-revocation.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateIssued, "fixture issue"); err != nil {
		t.Fatal(err)
	}
	cert := recordRevocationTestLeaf(t, h, owner.ID, identity.Name, "compound-test-ca", "compound-test-leaf", "")
	agentID := uuid.NewString()
	config, err := json.Marshal(map[string]any{"executor": "agent", "required_agent_id": agentID})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		Name: "compound-revocation-host", Type: "apache", Config: config,
		Enabled: false, EnabledSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
		IdentityID: &identity.ID, Destination: "connector.deploy", Connector: "apache", Target: target.Name,
		Fingerprint: cert.Fingerprint, Status: "verified", IdempotencyKey: "compound-fixture-deploy",
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateDeployed, "fixture served leaf"); err != nil {
		t.Fatal(err)
	}
	_, version, err := h.store.IdentityApprovalTarget(ctx, h.tenant, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	const key = "compound-CA-worker-exact"
	if _, err := h.orch.TransitionKeyCompromise(ctx, h.tenant, identity.ID, key, &version,
		orchestrator.EndpointContainmentRequest{
			TargetID: target.ID, TargetRevision: target.RevisionID, IdentityID: identity.ID,
			ExpectedFingerprint: cert.Fingerprint, RequiredAgentID: agentID,
			Connector: target.Type, Target: target.Name, Reason: "keyCompromise",
			RequestedBy: "incident-commander", IdempotencyKey: key,
		}); err != nil {
		t.Fatal(err)
	}
	seen := 0
	upstream := revocationTestCA{revoke: func(_ context.Context, req ca.RevokeRequest) error {
		if req.TenantID != h.tenant || req.Serial != cert.Serial || req.ReasonCode != 1 {
			t.Fatalf("wrong CA command: tenant=%s serial=%s reason=%d", req.TenantID, req.Serial, req.ReasonCode)
		}
		seen++
		return nil
	}}
	srv := &Server{orch: h.orch, outbox: h.outbox}
	if _, err := srv.buildExternalCAService(Deps{Store: h.store, Log: h.log, ExternalCAs: []ExternalCA{{
		ID: "compound-test-ca", Type: "vaultpki", Name: "compound test authority",
		Factory: func(context.Context) (ca.CA, func(), error) { return upstream, func() {}, nil },
	}}}, h.handler.idem); err != nil {
		t.Fatal(err)
	}
	h.handler.externalCAs = srv.externalCAs
	row := pendingOutboxByDestination(t, h, "revocation.publish")
	did, err := h.outbox.DispatchOneScoped(ctx, h.handler,
		orchestrator.DestinationScope{IncludePrefixes: []string{"revocation.publish"}})
	if err != nil || !did || seen != 1 {
		t.Fatalf("CA delivery did=%t seen=%d err=%v", did, seen, err)
	}
	got, _, err := h.orch.KeyCompromiseStatus(ctx, h.tenant, identity.ID, key)
	if err != nil || got.ID != row.ID || got.Status != "delivered" {
		t.Fatalf("live CA status = %+v, %v", got, err)
	}
	if tag, err := h.store.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id=$1 AND id=$2 AND destination='revocation.publish' AND status='delivered'`,
		h.tenant, row.ID); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("delivered outbox retention cleanup rows=%d err=%v", tag.RowsAffected(), err)
	}
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	got, _, err = h.orch.KeyCompromiseStatus(ctx, h.tenant, identity.ID, key)
	if err != nil || got.ID != row.ID || got.Status != "delivered" || got.DeliveredAt == nil ||
		time.Since(*got.DeliveredAt) > time.Minute {
		t.Fatalf("cold durable CA result = %+v, %v", got, err)
	}
}
