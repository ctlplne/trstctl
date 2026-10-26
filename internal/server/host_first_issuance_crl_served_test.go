// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A first issuance handed to a host agent mints nothing in the control plane:
// the agent generates the key and the certificate is signed when its CSR
// arrives. In a tenant that has issued no platform certificate yet there is no
// CRL to ensure at that moment, and the hand-off must still complete instead
// of retrying forever on a CRL it cannot have.
func TestServedHostFirstIssuanceCompletesInATenantWithNoCertificatesYet(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	agent := store.Agent{ID: uuid.NewString(), TenantID: h.tenant, Name: "web-host", Status: "active", Roles: []string{"host"}}
	if err := h.store.UpsertAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, string(store.OwnerTeam), "Web Team", "web@example.test")
	if err != nil {
		t.Fatal(err)
	}
	targetConfig, err := json.Marshal(map[string]string{
		"cert_path": "/etc/nginx/tls/web.crt", "key_path": "/etc/nginx/tls/web.key",
		"executor": "agent", "required_agent_id": agent.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		Name: "web-nginx", Type: "nginx", Config: targetConfig, Enabled: true, EnabledSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "web.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.BindIdentityDeploymentTarget(ctx, h.tenant, ident.ID, target); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.TransitionWithIdempotency(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "first issuance", "host-first-issuance"); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}

	var pending int
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'ca.issue' AND status <> 'delivered'`, h.tenant).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("%d first-issuance commands are still pending after the hand-off to the host agent", pending)
	}
	var queued int
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2 AND required_agent_id::text = $3`,
		h.tenant, agentJobKindEndpointRenew, agent.ID).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Fatalf("%d host renewal jobs queued, want the one first issuance", queued)
	}
}
