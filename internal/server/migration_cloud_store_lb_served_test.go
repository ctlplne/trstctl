// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/gcpcm"
	"trstctl.com/trstctl/internal/connector/gcpcm/gcpcmtest"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/migration"
)

// cloudLoadBalancer stands in for a provider's load balancer in front of a
// certificate store: it serves the stored certificate it has picked up, which
// lags the store until the test says the change has propagated.
type cloudLoadBalancer struct {
	serving atomic.Value // certificate id in the store
	addr    string
}

func newCloudLoadBalancer(t *testing.T, provider *gcpcmtest.Server) *cloudLoadBalancer {
	t.Helper()
	lb := &cloudLoadBalancer{}
	lb.serving.Store("")
	srv, err := tlsprobe.NewSwitchingTestServer(func() ([]byte, []byte, bool) {
		id, _ := lb.serving.Load().(string)
		stored, ok := provider.Imported(id)
		return stored.PEMCertificate, stored.PEMPrivateKey, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	lb.addr = srv.Addr
	return lb
}

func (lb *cloudLoadBalancer) serve(id string) { lb.serving.Store(id) }

// A166-L3: a cloud-store member's gate waits for the load balancer, not only
// the store. With the member's target naming the endpoint its load balancer
// answers on, a store that already serves the successor does not close the
// gate while the endpoint still presents the predecessor: the deploy row
// waits for the provider's propagation, rechecking without spending retries,
// and the member is verified once the endpoint presents the successor. A
// rollback whose re-bind the endpoint never picks up within the propagation
// window fails its gate and halts the run.
func TestServedCloudStoreGateWaitsForTheLoadBalancerA166L3(t *testing.T) {
	const (
		gcpToken = "a166l3-gcp-bearer-token" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
		certID   = "a166l3-web"
		mapEntry = "a166l3-map/a166l3-entry"
		dnsName  = "a166l3.served.test"
	)
	ctx := context.Background()
	provider := gcpcmtest.New(gcpToken)
	t.Cleanup(provider.Close)
	lb := newCloudLoadBalancer(t, provider)
	entry, err := gcpcm.ParseCertificateMapEntry(mapEntry)
	if err != nil {
		t.Fatal(err)
	}
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(provider.Client()) })
	registry.Register(gcpcm.New("a166l3-project", "global", gcpcm.StaticToken([]byte(gcpToken)),
		gcpcm.WithEndpoint(provider.URL()), gcpcm.WithPollInterval(0), gcpcm.WithCertificateMapEntry(entry)))
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ConnectorRegistry = registry
		d.DefaultProfile = "a166l3-api"
	})
	spec, _ := json.Marshal(map[string]any{"name": "a166l3-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "a166l3-api", spec); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": certID, "connector": "gcp-certificate-manager",
		"config": map[string]any{"project": "a166l3-project", "location": "global",
			"bearer_token_ref": "secret://connectors/gcp/a166l3", "certificate_map_entry": mapEntry,
			"verify_address": lb.addr, "verify_server_name": dnsName, "verify_private_egress_cidrs": []string{"127.0.0.1/32"}},
	})
	var target struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &target) != nil || target.ID == "" {
		t.Fatalf("create target: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "a166l3-owner"})
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
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+created.ID+"/transitions", tok, map[string]any{"to": "issued", "reason": "a166l3 predecessor"}); status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain predecessor: %v", err)
	}
	first := connectorDeliveriesForIdentity(t, h, tok, created.ID)
	if len(first.Items) != 1 || first.Items[0].Status != "delivered" {
		t.Fatalf("predecessor delivery = %+v", first.Items)
	}
	predecessorName := connector.DeployedObjectName(certID, first.Items[0].Fingerprint)
	lb.serve(predecessorName)
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

	caOperator := seedScopedTokenSubject(t, h.store, h.tenant, "a166l3-ca-operator", "issuers:read", "issuers:write")
	caApprover := seedScopedTokenSubject(t, h.store, h.tenant, "a166l3-ca-custodian", "issuers:read", "issuers:write")
	rootSpec := map[string]any{
		"common_name": "A166-L3 successor root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"served.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, caOperator, "create_root", "", rootSpec, 1, "a166l3-root-ceremony")
	approveCACeremony(t, h, caApprover, ceremony.ID, 1, "a166l3-root-approval")
	successorCA := createRootCA(t, h, caOperator, ceremony.ID, rootSpec, "a166l3-root-create")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a166l3-migration-operator", "keys:read", "keys:write", "certs:issue")
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/migrations/runs", operator, "a166l3-start", map[string]any{
		"plan_id": "plan-a166l3", "new_authority_id": successorCA.ID,
		"waves": []any{map[string]any{"id": "cloud", "ordinal": 1, "members": []any{map[string]any{"identity_id": created.ID}}}},
	})
	var started migration.Run
	if status != http.StatusCreated || json.Unmarshal(body, &started) != nil {
		t.Fatalf("start cloud-store migration = %d %s", status, body)
	}
	if b := started.Waves[0].Members[0].Binding; b.VerifyAddress != lb.addr || b.VerifyServerName != dnsName || b.ExecutionModel != "cloud_store" {
		t.Fatalf("the member binds %+v, want the load balancer's endpoint", b)
	}
	run := func() migration.RunMember {
		t.Helper()
		record, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
		if err != nil {
			t.Fatal(err)
		}
		return record.Run.Waves[0].Members[0]
	}
	runStatus := func() migration.RunStatus {
		t.Helper()
		record, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
		if err != nil {
			t.Fatal(err)
		}
		return record.Run.Status
	}
	row := func(stage string) (status, lastError string) {
		t.Helper()
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT status, coalesce(last_error, '') FROM outbox WHERE tenant_id=$1 AND idempotency_key LIKE $2 ORDER BY id DESC LIMIT 1`,
				h.tenant, "migration:"+started.ID+":%"+stage).Scan(&status, &lastError)
		}); err != nil {
			t.Fatalf("%s row: %v", stage, err)
		}
		return status, lastError
	}
	due := func(backdate time.Duration) {
		t.Helper()
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE outbox SET next_attempt_at = now(), created_at = created_at - $3::interval
			  WHERE tenant_id = $1 AND idempotency_key LIKE $2 AND status = 'pending'`,
				h.tenant, "migration:"+started.ID+":%", backdate.String())
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}

	// The store serves the successor at once; the load balancer still serves
	// the predecessor, so the gate waits.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the run: %v", err)
	}
	waiting := run()
	successorName := connector.DeployedObjectName(certID, waiting.Binding.SuccessorFingerprint)
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+successorName) {
		t.Fatalf("the store does not serve the successor: %v", bound)
	}
	if waiting.SuccessorVerdict != "" || runStatus() != migration.RunRunning {
		t.Fatalf("the gate closed while the load balancer served the predecessor: verdict %q, run %s", waiting.SuccessorVerdict, runStatus())
	}
	if status, lastError := row("cloud_store_deploy"); status != "pending" || lastError != "delivery_deferred" {
		t.Fatalf("the deploy row reads %s %q, want pending and deferred", status, lastError)
	}

	// The provider propagates the change: the next check closes the gate.
	lb.serve(successorName)
	due(0)
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain after propagation: %v", err)
	}
	if done := run(); done.SuccessorVerdict != migration.VerdictVerified || runStatus() != migration.RunComplete {
		t.Fatalf("after the load balancer served the successor: verdict %q, run %s", done.SuccessorVerdict, runStatus())
	}

	// A rollback re-binds the predecessor in the store, but the load balancer
	// never picks it up: past the propagation window the gate fails and the
	// run halts for the operator.
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/migrations/runs/"+started.ID+"/rollback", operator, "a166l3-rollback", map[string]any{"reason": "a166l3 rollback drill"})
	if status != http.StatusOK {
		t.Fatalf("rollback = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the rollback: %v", err)
	}
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+predecessorName) {
		t.Fatalf("the store does not serve the predecessor after the rollback: %v", bound)
	}
	if m := run(); m.RollbackSuccessorVerdict != "" || runStatus() != migration.RunRollingBack {
		t.Fatalf("the rollback gate closed while the load balancer served the successor: %q, run %s", m.RollbackSuccessorVerdict, runStatus())
	}
	due(time.Hour)
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain past the window: %v", err)
	}
	if m := run(); m.RollbackSuccessorVerdict != migration.VerdictFailed || runStatus() != migration.RunHalted {
		t.Fatalf("past the propagation window: verdict %q, run %s", m.RollbackSuccessorVerdict, runStatus())
	}
}
