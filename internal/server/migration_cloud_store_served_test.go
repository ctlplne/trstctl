// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
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

// A166 Done-when: a cloud certificate store migrates as an executable run
// member instead of being refused at start. In a tenant with no network relay
// the control plane's own client carries GCP Certificate Manager (A59), so the
// member names no agent: the control plane issues the successor under the new
// authority with the predecessor's exact identifiers, creates its
// fingerprint-named certificate and points the map entry at it, and the
// store's readback of that entry closes the live gate. An operator rollback
// re-binds the entry to the predecessor through the same client and the
// readback closes the rollback gate. A deploy or rollback row that spends its
// retries against a store that stays down is the member's failed receipt
// (A166-L4): the run rolls itself back, or halts naming the member, instead of
// waiting at its gate. A store whose API cannot restore a
// predecessor, a GCP target without a map entry, a trust path, and a tenant
// whose cloud-store work runs on a relay are each refused by name.
func TestServedMigrationCarriesACloudStoreFromTheControlPlane(t *testing.T) {
	const (
		gcpToken = "a166-gcp-bearer-token" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
		certID   = "a166-web"
		mapEntry = "a166-map/a166-entry"
		dnsName  = "a166.served.test"
	)
	ctx := context.Background()
	provider := gcpcmtest.New(gcpToken)
	t.Cleanup(provider.Close)
	entry, err := gcpcm.ParseCertificateMapEntry(mapEntry)
	if err != nil {
		t.Fatal(err)
	}
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(provider.Client()) })
	registry.Register(gcpcm.New("a166-project", "global", gcpcm.StaticToken([]byte(gcpToken)),
		gcpcm.WithEndpoint(provider.URL()), gcpcm.WithPollInterval(0), gcpcm.WithCertificateMapEntry(entry)))
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ConnectorRegistry = registry
		d.DefaultProfile = "a166-api"
	})
	spec, _ := json.Marshal(map[string]any{"name": "a166-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "a166-api", spec); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read")

	// The predecessor reaches the store the ordinary way: issued, then
	// delivered by the control plane as a fingerprint-named certificate the
	// map entry serves.
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": certID, "connector": "gcp-certificate-manager",
		"config": map[string]any{"project": "a166-project", "location": "global",
			"bearer_token_ref": "secret://connectors/gcp/a166", "certificate_map_entry": mapEntry},
	})
	var target struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &target) != nil || target.ID == "" {
		t.Fatalf("create target: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "a166-owner"})
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
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+created.ID+"/transitions", tok, map[string]any{"to": "issued", "reason": "a166 predecessor"}); status != http.StatusOK {
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
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+predecessorName) {
		t.Fatalf("map entry before the run = %v", bound)
	}
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
	predecessor, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, predecessorFP)
	if err != nil || predecessor.Status != "active" {
		t.Fatalf("predecessor = %+v %v", predecessor, err)
	}

	// Two stores a run could not put back, deployed on paper only: their
	// refusal comes before any predecessor is read.
	refusedMember := func(name, family string, config map[string]any) string {
		raw, _ := json.Marshal(config)
		refused, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: name, Type: family, Config: raw, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		attrs, _ := json.Marshal(map[string]string{"deployment_target_id": refused.ID, "connector": family, "target": name})
		id, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: name + ".served.test", OwnerID: owner.ID, Attributes: attrs})
		if err != nil {
			t.Fatal(err)
		}
		id.Status = "deployed"
		if err := h.store.UpsertIdentity(ctx, id); err != nil {
			t.Fatal(err)
		}
		return id.ID
	}
	acmIdentity := refusedMember("a166-acm", "aws-acm", map[string]any{"region": "us-east-1", "certificate_arn": "arn:aws:acm:us-east-1:111111111111:certificate/a166"})
	inPlaceIdentity := refusedMember("a166-in-place", "gcp-certificate-manager", map[string]any{"project": "a166-project", "location": "global"})

	caOperator := seedScopedTokenSubject(t, h.store, h.tenant, "a166-ca-operator", "issuers:read", "issuers:write")
	caApprover := seedScopedTokenSubject(t, h.store, h.tenant, "a166-ca-custodian", "issuers:read", "issuers:write")
	rootSpec := map[string]any{
		"common_name": "A166 successor root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"served.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, caOperator, "create_root", "", rootSpec, 1, "a166-root-ceremony")
	approveCACeremony(t, h, caApprover, ceremony.ID, 1, "a166-root-approval")
	successorCA := createRootCA(t, h, caOperator, ceremony.ID, rootSpec, "a166-root-create")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a166-migration-operator", "keys:read", "keys:write", "certs:issue")
	start := func(planID, identityID, trustPath, key string) (int, []byte) {
		member := map[string]any{"identity_id": identityID}
		if trustPath != "" {
			member["trust_anchor_path"] = trustPath
		}
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/migrations/runs", operator, key, map[string]any{
			"plan_id": planID, "new_authority_id": successorCA.ID,
			"waves": []any{map[string]any{"id": "cloud", "ordinal": 1, "members": []any{member}}},
		})
	}
	for _, refusal := range []struct {
		name, identityID, trustPath, want string
	}{
		{"an in-place store", acmIdentity, "", "re-imports in place under one certificate ARN"},
		{"a target without a map entry", inPlaceIdentity, "", "names no certificate_map_entry"},
		{"a trust path", created.ID, "/etc/ssl/next.pem", "a cloud-store member takes no trust_anchor_path"},
	} {
		status, body := start("plan-a166-"+refusal.identityID[:8], refusal.identityID, refusal.trustPath, "a166-refuse-"+refusal.name)
		if status != http.StatusBadRequest || !bytes.Contains(body, []byte(refusal.want)) {
			t.Fatalf("%s: start = %d %s; want 400 naming %q", refusal.name, status, body, refusal.want)
		}
	}

	status, body = start("plan-a166", created.ID, "", "a166-start")
	var started migration.Run
	if status != http.StatusCreated || json.Unmarshal(body, &started) != nil {
		t.Fatalf("start cloud-store migration = %d %s", status, body)
	}
	member := started.Waves[0].Members[0]
	if started.Status != migration.RunRunning || started.Waves[0].Phase != migration.PhaseVerifyingLive ||
		member.TrustVerdict != migration.VerdictNotApplicable || member.Binding.ExecutionModel != "cloud_store" ||
		member.Binding.RequiredAgentID != "" || member.Binding.TrustAnchorPath != "" ||
		member.Binding.PredecessorCertificateID != predecessor.ID {
		t.Fatalf("started run = %s", body)
	}

	// The control plane issues the successor and installs it itself; the
	// store's readback of the map entry closes the gate.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the run: %v", err)
	}
	var role, rowStatus string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT required_agent_role, status FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`,
			h.tenant, "migration:"+started.ID+":cloud:"+created.ID+":cloud_store_deploy").Scan(&role, &rowStatus)
	}); err != nil {
		t.Fatalf("cloud-store deploy row: %v", err)
	}
	if role != string(connector.VantageControlPlane) || rowStatus != "delivered" {
		t.Fatalf("cloud-store deploy row = role %q status %q", role, rowStatus)
	}
	finished, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	done := finished.Run.Waves[0].Members[0]
	successorFP := done.Binding.SuccessorFingerprint
	if finished.Run.Status != migration.RunComplete || done.SuccessorVerdict != migration.VerdictVerified || successorFP == "" || successorFP == predecessorFP {
		t.Fatalf("after the control plane's readback: %+v", finished.Run)
	}
	successorName := connector.DeployedObjectName(certID, successorFP)
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+successorName) {
		t.Fatalf("map entry after the run = %v, want %q", bound, successorName)
	}
	if _, ok := provider.Imported(predecessorName); !ok {
		t.Fatal("the migration removed the predecessor certificate; a rollback could not re-bind it")
	}
	successor, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, successorFP)
	if err != nil || successor.ReplacesID == nil || *successor.ReplacesID != predecessor.ID || len(successor.SANs) != 1 || successor.SANs[0] != dnsName {
		t.Fatalf("successor = %+v %v, want the predecessor's exact name under the new authority", successor, err)
	}
	if superseded, err := h.store.GetCertificate(ctx, h.tenant, predecessor.ID); err != nil || superseded.Status != "superseded" {
		t.Fatalf("predecessor after the run = %+v %v, want superseded", superseded, err)
	}
	receipt, found, err := h.store.LatestServedCertificateReceipt(ctx, h.tenant, created.ID)
	if err != nil || !found || receipt.Fingerprint != successorFP ||
		!strings.HasPrefix(receipt.IdempotencyKey, "migration:"+started.ID+":cloud:") {
		t.Fatalf("latest served receipt = %+v found=%v err=%v", receipt, found, err)
	}

	// The operator rolls the run back: the control plane re-binds the entry
	// to the predecessor and the readback closes the rollback gate.
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/migrations/runs/"+started.ID+"/rollback", operator, "a166-rollback", map[string]any{"reason": "a166 rollback drill"})
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
	if rolled.Run.Status != migration.RunRolledBack || rolled.Run.Waves[0].Members[0].RollbackSuccessorVerdict != migration.VerdictVerified ||
		rolled.Run.Waves[0].Members[0].RollbackTrustVerdict != migration.VerdictNotApplicable {
		t.Fatalf("after the rollback: %+v", rolled.Run)
	}
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+predecessorName) {
		t.Fatalf("map entry after the rollback = %v, want the predecessor %q", bound, predecessorName)
	}

	// A166-L4: the store goes down after a second run starts and stays down
	// while the control plane's deploy spends its retries. The spent row is
	// the member's failed receipt, as a relay's would be, so the run rolls
	// itself back instead of waiting at its gate; the rollback row spends its
	// retries too and halts the run naming the member. Once the store is back
	// the operator's one rollback retry re-binds the predecessor.
	status, body = start("plan-a166-down", created.ID, "", "a166-start-down")
	var down migration.Run
	if status != http.StatusCreated || json.Unmarshal(body, &down) != nil {
		t.Fatalf("start the outage run = %d %s", status, body)
	}
	provider.SetUnavailable(true)
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the outage run: %v", err)
	}
	spend := func(destination, keyPrefix string) {
		t.Helper()
		var key string
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT idempotency_key FROM outbox
			   WHERE tenant_id = $1 AND destination = $2 AND status = 'pending' AND starts_with(idempotency_key, $3)`,
				h.tenant, destination, keyPrefix).Scan(&key)
		}); err != nil {
			t.Fatalf("pending %s row %s: %v", destination, keyPrefix, err)
		}
		// One attempt short of the outbox's limit, so the next failure is its last.
		tag, err := h.store.SystemPool().Exec(ctx, `UPDATE outbox SET attempts = 9, next_attempt_at = now()
		   WHERE tenant_id = $1 AND idempotency_key = $2 AND status = 'pending'`, h.tenant, key)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("arm %s: %v %v", key, tag, err)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatalf("drain %s: %v", key, err)
		}
		var rowStatus string
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT status FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, h.tenant, key).Scan(&rowStatus)
		}); err != nil || rowStatus != "failed" {
			t.Fatalf("%s after its last attempt = %q %v, want failed", key, rowStatus, err)
		}
	}
	memberKey := "migration:" + down.ID + ":cloud:" + created.ID + ":"
	spend("connector.deploy", memberKey+"cloud_store_deploy")
	outage, err := h.store.GetMigrationRun(ctx, h.tenant, down.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := outage.Run.Waves[0].Members[0]; got.SuccessorVerdict != migration.VerdictFailed || outage.Run.Status != migration.RunRollingBack {
		t.Fatalf("after the deploy spent its retries: status %q successor verdict %q, want rolling_back on a failed verdict (the run waited at its gate)",
			outage.Run.Status, got.SuccessorVerdict)
	}
	spend("connector.rollback", memberKey)
	halted, err := h.store.GetMigrationRun(ctx, h.tenant, down.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := halted.Run.Waves[0].Members[0]; got.RollbackSuccessorVerdict != migration.VerdictFailed ||
		halted.Run.Status != migration.RunHalted || !strings.Contains(halted.Run.HaltReason, created.ID) {
		t.Fatalf("after the rollback spent its retries: status %q halt %q rollback verdict %q, want halted naming the member",
			halted.Run.Status, halted.Run.HaltReason, got.RollbackSuccessorVerdict)
	}
	provider.SetUnavailable(false)
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/migrations/runs/"+down.ID+"/rollback", operator, "a166-rollback-down", map[string]any{"reason": "a166 store is back"})
	if status != http.StatusOK {
		t.Fatalf("retry the halted rollback = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the retried rollback: %v", err)
	}
	healed, err := h.store.GetMigrationRun(ctx, h.tenant, down.ID)
	if err != nil {
		t.Fatal(err)
	}
	if healed.Run.Status != migration.RunRolledBack || healed.Run.Waves[0].Members[0].RollbackSuccessorVerdict != migration.VerdictVerified {
		t.Fatalf("after the store came back: %+v", healed.Run)
	}
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+predecessorName) {
		t.Fatalf("map entry after the outage run = %v, want the predecessor %q", bound, predecessorName)
	}

	// Once a relay is enrolled the store's work runs there, so a new run must
	// name it rather than bind the control plane.
	if err := h.store.UpsertAgent(ctx, store.Agent{ID: "16616616-6166-4166-8166-166166166166", TenantID: h.tenant, Name: "a166-relay", Status: "active", Roles: []string{mtls.AgentRoleNetwork}}); err != nil {
		t.Fatal(err)
	}
	status, body = start("plan-a166-relay", created.ID, "", "a166-start-relay")
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("network relay enrolled")) {
		t.Fatalf("start with a relay enrolled = %d %s; want 400 naming the relay", status, body)
	}
}
