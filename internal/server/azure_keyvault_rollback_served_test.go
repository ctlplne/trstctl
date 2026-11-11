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
	"trstctl.com/trstctl/internal/connector/azurekv"
	"trstctl.com/trstctl/internal/connector/azurekv/azurekvtest"
)

// A166-L1: an Azure Key Vault target is rollable through the served route. Key
// Vault keeps every imported version and serves the newest by name, so the
// rollback, queued as a control_plane row no agent can claim and executed by
// the outbox worker, finds the predecessor's version by fingerprint, reads that
// version's retained secret and imports it as the newest version. The vault
// then serves the predecessor again, its key read from the vault's own copy,
// and the receipt says so. Before, the route refused Key Vault ("serves the
// newest version").
func TestServedAzureKeyVaultRollbackReimportsThePredecessorVersionA166L1(t *testing.T) {
	const (
		kvToken = "stand-in-vault-token" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
		certID  = "web-prod"
	)
	vault := azurekvtest.New(kvToken)
	t.Cleanup(vault.Close)
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(vault.Client()) })
	registry.Register(azurekv.New(vault.URL(), azurekv.StaticToken([]byte(kvToken))))
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
		d.ConnectorRegistry = registry
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read",
	)
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": certID, "connector": "azure-keyvault",
		"config": map[string]any{"endpoint": vault.URL(), "bearer_token_ref": "secret://connectors/akv/a166l1"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: status %d body %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &target); err != nil || target.ID == "" {
		t.Fatalf("decode target: %v %s", err, body)
	}
	call := func(method, path string, in any, want int) []byte {
		t.Helper()
		status, body := secretsReq(t, h, method, path, tok, in)
		if status != want {
			t.Fatalf("%s %s = %d %s", method, path, status, body)
		}
		return body
	}
	var owner, ident struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(call(http.MethodPost, "/api/v1/owners", map[string]any{"kind": "workload", "name": "a166l1-owner"}, http.StatusCreated), &owner)
	_ = json.Unmarshal(call(http.MethodPost, "/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "a166l1.served.test", "owner_id": owner.ID}, http.StatusCreated), &ident)
	call(http.MethodPost, "/api/v1/identities/"+ident.ID+"/connector-target", map[string]any{"target_id": target.ID}, http.StatusOK)
	call(http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", map[string]any{"to": "issued", "reason": "a166l1 issue"}, http.StatusOK)
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue and deploy: %v", err)
	}
	first := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	if len(first.Items) != 1 || first.Items[0].Status != "delivered" {
		t.Fatalf("first delivery = %+v raw=%s", first.Items, first.Raw)
	}
	predecessor, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, first.Items[0].Fingerprint)
	if err != nil || predecessor.NotAfter == nil {
		t.Fatalf("load delivered leaf: %+v %v", predecessor, err)
	}
	if queued, err := h.srv.runLifecycleOnceAt(t.Context(), predecessor.NotAfter.Add(-12*time.Hour)); err != nil || queued != 1 {
		t.Fatalf("scheduled renewals = %d %v, want 1", queued, err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain renewal: %v", err)
	}
	if versions := vault.Versions(certID); len(versions) != 2 || bytes.Contains(versions[1].PEM, predecessor.CertificatePEM) {
		t.Fatalf("vault versions after the renewal = %d; want two, the newest the successor", len(versions))
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/connectors/targets/"+target.ID, tok, nil)
	var readiness struct {
		RollbackReadiness struct {
			Model                  string `json:"model"`
			Ready                  bool   `json:"ready"`
			Reason                 string `json:"reason"`
			PredecessorFingerprint string `json:"predecessor_fingerprint"`
		} `json:"rollback_readiness"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &readiness) != nil || !readiness.RollbackReadiness.Ready ||
		readiness.RollbackReadiness.PredecessorFingerprint != predecessor.Fingerprint {
		t.Fatalf("rollback readiness after the renewal = %d %s; want ready on the predecessor", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/rollback", tok, map[string]any{
		"identity_id": ident.ID, "reason": "a166l1 rollback drill",
	})
	if status != http.StatusOK || !jsonContains(t, body, "rollback_queued") {
		t.Fatalf("rollback request: status %d body %s", status, body)
	}
	var role string
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT required_agent_role FROM outbox WHERE tenant_id=$1 AND destination='connector.rollback' ORDER BY id DESC LIMIT 1`,
			h.tenant).Scan(&role)
	}); err != nil || role != string(connector.VantageControlPlane) {
		t.Fatalf("rollback row required_agent_role = %q (%v), want control_plane", role, err)
	}
	if vault.SecretReads() != 0 {
		t.Fatal("the rollback request handler read the vault; only the outbox worker may")
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain rollback: %v", err)
	}
	versions := vault.Versions(certID)
	if len(versions) != 3 || !bytes.Contains(versions[2].PEM, predecessor.CertificatePEM) || !versions[2].Exportable || vault.SecretReads() != 1 {
		t.Fatalf("vault after the rollback: %d versions, %d secret reads; want the predecessor imported again as the newest from one read of its own version", len(versions), vault.SecretReads())
	}
	afterRollback := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	found := false
	for _, item := range afterRollback.Items {
		if item.Destination != "connector.rollback" || item.Status == "rollback_queued" {
			continue
		}
		found = true
		if item.Status != "rolled_back" || item.Fingerprint != predecessor.Fingerprint || item.Connector != "azure-keyvault" ||
			!strings.Contains(item.Detail, "importing the provider's own retained copy of that version") {
			t.Fatalf("rollback result receipt = %+v", item)
		}
	}
	if !found {
		t.Fatalf("no rollback result receipt was recorded: %s", afterRollback.Raw)
	}
}
