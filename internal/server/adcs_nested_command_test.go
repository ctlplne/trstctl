// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/store"
)

func TestServedADCSNestedCommandCannotBeAlteredBeforeClaimOrRedemption(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, adcs.NestedGroupsJobKind)
	ctx := t.Context()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a228-old", Status: "active", Executors: &transport.ExecutorReport{Version: "a228-old", Kinds: []transport.ExecutorKind{{Kind: adcs.JobKind}}}}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	config := map[string]any{"url": "ldaps://dc.example", "configuration_dn": "CN=Configuration,DC=example", "bind_dn": "CN=reader,DC=example", "password_ref": "secret://adcs/a228-reader", "relay_agent_id": agentRowID(h.tenant, h.agent), "nested_groups_enabled": true, "membership_domain_dn": "DC=example"} // #nosec G101 -- public secret:// reference fixture; contains no credential value (CWE-798).
	preview := map[string]any{"kind": adcs.SourceKind, "config": config}
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/plans/preview", token, "", preview)
	if code != 200 {
		t.Fatalf("preview=%d %s", code, body)
	}
	var readiness struct {
		Ready          bool     `json:"ready"`
		BlockedReasons []string `json:"blocked_reasons"`
	}
	if err := json.Unmarshal(body, &readiness); err != nil {
		t.Fatal(err)
	}
	if readiness.Ready || len(readiness.BlockedReasons) == 0 {
		t.Fatalf("old relay could silently ignore nested settings: %s", body)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a228-new", Status: "active", Executors: &transport.ExecutorReport{Version: "a228-new", Kinds: []transport.ExecutorKind{{Kind: adcs.NestedGroupsJobKind}}}}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(config)
	source, err := h.srv.orch.UpsertDiscoverySource(ctx, h.tenant, store.DiscoverySource{Kind: adcs.SourceKind, Name: "a228-command-fences", Config: raw})
	if err != nil {
		t.Fatal(err)
	}
	run, err := h.srv.orch.QueueDiscoveryRun(ctx, h.tenant, store.DiscoveryRun{SourceID: source.ID})
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	var key string
	var payload []byte
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id,idempotency_key,payload FROM outbox WHERE tenant_id=$1 AND destination=$2`, h.tenant, adcs.NestedGroupsJobKind).Scan(&id, &key, &payload)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.BoundADCSNestedCommand(ctx, h.tenant, key, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.BoundADCSNestedCommand(ctx, "22222222-2222-4222-8222-222222222222", key, payload); err == nil {
		t.Fatal("another tenant adopted the command")
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if healed, err := h.srv.orch.ReconcileOutbox(ctx, h.log); err != nil || healed != 1 {
		t.Fatalf("lost outbox recovery=%d %v", healed, err)
	}
	var command adcs.InventoryIntent
	if err := json.Unmarshal(payload, &command); err != nil {
		t.Fatal(err)
	}
	command.PasswordRef = "secret://adcs/a228-unapproved" // #nosec G101 -- a public reference fixture, no credential value (CWE-798).
	altered, _ := json.Marshal(command)
	if _, err := h.srv.orch.BoundADCSNestedCommand(ctx, h.tenant, key, altered); err == nil {
		t.Fatal("changed credential reference passed immutable binding")
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET payload=$3 WHERE tenant_id=$1 AND destination=$2`, h.tenant, adcs.NestedGroupsJobKind, altered)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	claims, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{adcs.NestedGroupsJobKind}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claims.Jobs) != 0 {
		t.Fatalf("altered nested command handed out: %v %v", claims, err)
	}
	var attempt int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id,claim_attempts FROM outbox WHERE tenant_id=$1 AND destination=$2`, h.tenant, adcs.NestedGroupsJobKind).Scan(&id, &attempt)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: id, Attempt: attempt}); err == nil {
		t.Fatal("altered nested command redeemed a credential")
	}
	current, err := h.store.GetDiscoveryRun(ctx, h.tenant, run.ID)
	if err != nil || current.Status != "queued" {
		t.Fatalf("refused claim invented running=%s %v", current.Status, err)
	}
}

func TestServedADCSNestedClaimRequiresCertificateNetworkRole(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, adcs.NestedGroupsJobKind)
	ctx := t.Context()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a228-host", Status: "active", Executors: &transport.ExecutorReport{Version: "a228-host", Kinds: []transport.ExecutorKind{{Kind: adcs.NestedGroupsJobKind}}}}); err != nil {
		t.Fatal(err)
	}
	// The read model can be damaged. Neither an agent row nor an outbox row can
	// confer the network role absent from the authenticated certificate.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE agents SET roles=ARRAY['network']::text[] WHERE tenant_id=$1 AND id=$2`, h.tenant, agentRowID(h.tenant, h.agent))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"url": "ldaps://dc.example", "configuration_dn": "CN=Configuration,DC=example", "bind_dn": "CN=reader,DC=example", "password_ref": "secret://adcs/a228-reader", "relay_agent_id": agentRowID(h.tenant, h.agent), "nested_groups_enabled": true, "membership_domain_dn": "DC=example"}) // #nosec G101 -- public secret:// reference fixture; contains no credential value (CWE-798).
	source, err := h.srv.orch.UpsertDiscoverySource(ctx, h.tenant, store.DiscoverySource{Kind: adcs.SourceKind, Name: "a228-role-fence", Config: raw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.QueueDiscoveryRun(ctx, h.tenant, store.DiscoveryRun{SourceID: source.ID}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET required_agent_role='host' WHERE tenant_id=$1 AND destination=$2`, h.tenant, adcs.NestedGroupsJobKind)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	claims, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{adcs.NestedGroupsJobKind}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claims.Jobs) != 0 {
		t.Fatalf("SQL roles granted directory work to a host certificate: count=%d err=%v", len(claims.Jobs), err)
	}
}
