// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/gcpcm"
	"trstctl.com/trstctl/internal/connector/gcpcm/gcpcmtest"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/store"
)

// TestServedRelayEnrolledMidRunLeavesTheControlPlanesMemberA166L5 is
// A166-L5's Done-when (served): a cloud-store member bound to the control
// plane when its run started (no network relay then) stays the control
// plane's for the whole run. A network relay enrolls after the run starts and
// before the member's deploy runs: the control plane still installs the
// successor and reads the store back to close the live gate, and an operator
// rollback is still executed and read back by the control plane; no row of
// the run is ever queued for the relay or a network role. Only a new run is
// refused, naming the relay.
func TestServedRelayEnrolledMidRunLeavesTheControlPlanesMemberA166L5(t *testing.T) {
	const (
		gcpToken = "a166l5-gcp-bearer-token" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
		certID   = "a166l5-web"
		mapEntry = "a166l5-map/a166l5-entry"
		dnsName  = "a166l5.served.test"
		relayID  = "16616616-6166-4166-8166-1661661665a5"
	)
	ctx := context.Background()
	provider := gcpcmtest.New(gcpToken)
	t.Cleanup(provider.Close)
	entry, err := gcpcm.ParseCertificateMapEntry(mapEntry)
	if err != nil {
		t.Fatal(err)
	}
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(provider.Client()) })
	registry.Register(gcpcm.New("a166l5-project", "global", gcpcm.StaticToken([]byte(gcpToken)),
		gcpcm.WithEndpoint(provider.URL()), gcpcm.WithPollInterval(0), gcpcm.WithCertificateMapEntry(entry)))
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ConnectorRegistry = registry
		d.DefaultProfile = "a166l5-api"
	})
	spec, _ := json.Marshal(map[string]any{"name": "a166l5-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "a166l5-api", spec); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read")

	// The predecessor reaches the store the ordinary way.
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": certID, "connector": "gcp-certificate-manager",
		"config": map[string]any{"project": "a166l5-project", "location": "global",
			"bearer_token_ref": "secret://connectors/gcp/a166l5", "certificate_map_entry": mapEntry},
	})
	var target struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &target) != nil || target.ID == "" {
		t.Fatalf("create target: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "a166l5-owner"})
	var owner struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &owner) != nil {
		t.Fatalf("create owner: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind": "x509_certificate", "name": dnsName, "owner_id": owner.ID,
	})
	var created struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &created) != nil {
		t.Fatalf("create identity: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+created.ID+"/connector-target", tok, map[string]any{"target_id": target.ID}); status != http.StatusOK {
		t.Fatalf("bind identity: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+created.ID+"/transitions", tok, map[string]any{"to": "issued", "reason": "a166l5 predecessor"}); status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain predecessor: %v", err)
	}
	first := connectorDeliveriesForIdentity(t, h, tok, created.ID)
	if len(first.Items) != 1 || first.Items[0].Status != "delivered" {
		t.Fatalf("predecessor delivery = %+v", first.Items)
	}
	predecessorFP := first.Items[0].Fingerprint
	predecessorName := connector.DeployedObjectName(certID, predecessorFP)
	ident, err := h.store.GetIdentity(ctx, h.tenant, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ident.Status != "deployed" {
		ident.Status = "deployed"
		if err := h.store.UpsertIdentity(ctx, ident); err != nil {
			t.Fatal(err)
		}
	}

	caOperator := seedScopedTokenSubject(t, h.store, h.tenant, "a166l5-ca-operator", "issuers:read", "issuers:write")
	caApprover := seedScopedTokenSubject(t, h.store, h.tenant, "a166l5-ca-custodian", "issuers:read", "issuers:write")
	rootSpec := map[string]any{
		"common_name": "A166-L5 successor root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"served.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, caOperator, "create_root", "", rootSpec, 1, "a166l5-root-ceremony")
	approveCACeremony(t, h, caApprover, ceremony.ID, 1, "a166l5-root-approval")
	successorCA := createRootCA(t, h, caOperator, ceremony.ID, rootSpec, "a166l5-root-create")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a166l5-migration-operator", "keys:read", "keys:write", "certs:issue")
	start := func(planID, key string) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/migrations/runs", operator, key, map[string]any{
			"plan_id": planID, "new_authority_id": successorCA.ID,
			"waves": []any{map[string]any{"id": "cloud", "ordinal": 1, "members": []any{map[string]any{"identity_id": created.ID}}}},
		})
	}

	// No relay yet: the member is bound to the control plane.
	status, body = start("plan-a166l5", "a166l5-start")
	var started migration.Run
	if status != http.StatusCreated || json.Unmarshal(body, &started) != nil {
		t.Fatalf("start cloud-store migration = %d %s", status, body)
	}
	if member := started.Waves[0].Members[0]; member.Binding.ExecutionModel != "cloud_store" || member.Binding.RequiredAgentID != "" {
		t.Fatalf("started member binding = %+v, want the control plane's", member.Binding)
	}

	// A network relay enrolls mid-run, before the member's deploy runs.
	if err := h.store.UpsertAgent(ctx, store.Agent{ID: relayID, TenantID: h.tenant, Name: "a166l5-relay", Status: "active", Roles: []string{mtls.AgentRoleNetwork}}); err != nil {
		t.Fatal(err)
	}
	if has, err := h.store.TenantHasNetworkRelay(ctx, h.tenant); err != nil || !has {
		t.Fatalf("the tenant reads no network relay after enrolling one: %v %v", has, err)
	}

	// The control plane still installs the successor and its readback closes
	// the live gate.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the run: %v", err)
	}
	finished, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	done := finished.Run.Waves[0].Members[0]
	if finished.Run.Status != migration.RunComplete || done.SuccessorVerdict != migration.VerdictVerified ||
		done.Binding.ExecutionModel != "cloud_store" || done.Binding.RequiredAgentID != "" {
		t.Fatalf("after the relay enrolled mid-run: status %q verdict %q binding %+v", finished.Run.Status, done.SuccessorVerdict, done.Binding)
	}
	successorName := connector.DeployedObjectName(certID, done.Binding.SuccessorFingerprint)
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+successorName) {
		t.Fatalf("map entry after the run = %v, want %q", bound, successorName)
	}

	// The operator's rollback is executed and read back by the control plane
	// too.
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/migrations/runs/"+started.ID+"/rollback", operator, "a166l5-rollback", map[string]any{"reason": "a166l5 rollback drill"})
	if status != http.StatusOK {
		t.Fatalf("rollback = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the rollback: %v", err)
	}
	rolled, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Run.Status != migration.RunRolledBack || rolled.Run.Waves[0].Members[0].RollbackSuccessorVerdict != migration.VerdictVerified {
		t.Fatalf("after the rollback: %+v", rolled.Run)
	}
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+predecessorName) {
		t.Fatalf("map entry after the rollback = %v, want the predecessor %q", bound, predecessorName)
	}

	// Every row the run queued ran on the control plane; none names the relay.
	type row struct{ destination, role, agent, status string }
	var rows []row
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `SELECT destination, required_agent_role, COALESCE(required_agent_id::text, ''), status FROM outbox
			 WHERE tenant_id = $1 AND starts_with(idempotency_key, $2) ORDER BY id`, h.tenant, "migration:"+started.ID+":")
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var one row
			if err := r.Scan(&one.destination, &one.role, &one.agent, &one.status); err != nil {
				return err
			}
			rows = append(rows, one)
		}
		return r.Err()
	}); err != nil {
		t.Fatal(err)
	}
	deploys, rollbacks := 0, 0
	for _, r := range rows {
		if r.role == mtls.AgentRoleNetwork || r.agent != "" {
			t.Fatalf("a row of the run was queued for a relay: %+v (all: %+v)", r, rows)
		}
		switch r.destination {
		case "connector.deploy":
			deploys++
		case "connector.rollback":
			rollbacks++
		}
		if (r.destination == "connector.deploy" || r.destination == "connector.rollback") &&
			(r.role != string(connector.VantageControlPlane) || r.status != "delivered") {
			t.Fatalf("%s row = role %q status %q, want delivered by the control plane", r.destination, r.role, r.status)
		}
	}
	if deploys != 1 || rollbacks != 1 {
		t.Fatalf("the run queued %d deploy and %d rollback rows, want one each: %+v", deploys, rollbacks, rows)
	}

	// Only a new run is refused, naming the relay.
	if status, body := start("plan-a166l5-next", "a166l5-start-next"); status != http.StatusBadRequest || !strings.Contains(string(body), "network relay enrolled") {
		t.Fatalf("a new run with the relay enrolled = %d %s; want 400 naming the relay", status, body)
	}
	t.Logf("A166L5_OK run=%s stayed on the control plane", started.ID)
}
