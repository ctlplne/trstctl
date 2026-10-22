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
)

// A58: a GCP Certificate Manager target that names a certificate map entry is
// rollable through the served route. Deploys create fingerprint-named
// certificates and point the entry at them; the rollback is queued as a
// control_plane row no agent can claim, executed by the outbox worker against
// the provider API, and recorded as a rolled_back receipt of the same shape an
// agent's would be. No key is uploaded by the rollback.
func TestServedGCPCertificateManagerRollbackRepointsTheMapEntryFromTheControlPlane(t *testing.T) {
	const (
		gcpToken = "a58-gcp-bearer-token" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		certID   = "web-prod"
		mapEntry = "web-map/web-entry"
	)
	provider := gcpcmtest.New(gcpToken)
	t.Cleanup(provider.Close)
	entry, err := gcpcm.ParseCertificateMapEntry(mapEntry)
	if err != nil {
		t.Fatal(err)
	}
	registry := connector.NewRegistry(func(string) connector.Ops {
		return connector.NewHTTPOps(provider.Client())
	})
	registry.Register(gcpcm.New("a58-project", "global", gcpcm.StaticToken([]byte(gcpToken)),
		gcpcm.WithEndpoint(provider.URL()), gcpcm.WithPollInterval(0), gcpcm.WithCertificateMapEntry(entry)))
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
		d.ConnectorRegistry = registry
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": certID, "connector": "gcp-certificate-manager",
		"config": map[string]any{
			"project": "a58-project", "location": "global",
			"bearer_token_ref": "secret://connectors/gcp/a58", "certificate_map_entry": mapEntry,
		},
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
	readiness := func() (model string, ready bool, reason, predecessor string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/targets/"+target.ID, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("get target = %d %s", status, body)
		}
		var out struct {
			RollbackReadiness *struct {
				Model                  string `json:"model"`
				Ready                  bool   `json:"ready"`
				Reason                 string `json:"reason"`
				PredecessorFingerprint string `json:"predecessor_fingerprint"`
			} `json:"rollback_readiness"`
		}
		if err := json.Unmarshal(body, &out); err != nil || out.RollbackReadiness == nil {
			t.Fatalf("target carries no rollback_readiness: %v %s", err, body)
		}
		r := out.RollbackReadiness
		return r.Model, r.Ready, r.Reason, r.PredecessorFingerprint
	}
	if model, ready, reason, _ := readiness(); model != "re-bind" || ready || !strings.Contains(reason, "no identity is bound") {
		t.Fatalf("readiness before binding = %q %v %q", model, ready, reason)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "a58-owner"})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind": "x509_certificate", "name": "a58.served.test", "owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/connector-target", tok, map[string]any{"target_id": target.ID})
	if status != http.StatusOK {
		t.Fatalf("bind identity to target: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to": "issued", "reason": "a58 issue after target binding",
	})
	if status != http.StatusOK {
		t.Fatalf("issue: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue and deploy: %v", err)
	}
	first := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	if len(first.Items) != 1 || first.Items[0].Status != "delivered" || first.Items[0].Fingerprint == "" {
		t.Fatalf("first delivery = %+v raw=%s", first.Items, first.Raw)
	}
	firstName := connector.DeployedObjectName(certID, first.Items[0].Fingerprint)
	if _, ok := provider.Imported(firstName); !ok {
		t.Fatalf("the first deploy did not create the fingerprint-named certificate %q", firstName)
	}
	if _, ok := provider.Imported(certID); ok {
		t.Fatal("a map-entry deploy patched the target-named certificate in place")
	}
	if model, ready, reason, _ := readiness(); model != "re-bind" || ready || !strings.Contains(reason, "no predecessor certificate") {
		t.Fatalf("readiness after one deploy = %q %v %q", model, ready, reason)
	}

	leaf, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, first.Items[0].Fingerprint)
	if err != nil || leaf.NotAfter == nil {
		t.Fatalf("load delivered leaf: %+v %v", leaf, err)
	}
	if queued, err := h.srv.runLifecycleOnceAt(t.Context(), leaf.NotAfter.Add(-12*time.Hour)); err != nil || queued != 1 {
		t.Fatalf("scheduled renewals = %d %v, want 1", queued, err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain renewal: %v", err)
	}
	afterRenew := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	if len(afterRenew.Items) != 2 {
		t.Fatalf("deliveries after renewal = %d (%s)", len(afterRenew.Items), afterRenew.Raw)
	}
	var secondFP string
	for _, item := range afterRenew.Items {
		if item.Fingerprint != first.Items[0].Fingerprint {
			secondFP = item.Fingerprint
		}
	}
	secondName := connector.DeployedObjectName(certID, secondFP)
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+secondName) {
		t.Fatalf("map entry after renewal = %v, want %q", bound, secondName)
	}
	if _, ok := provider.Imported(firstName); !ok {
		t.Fatal("the renewal removed the predecessor certificate; nothing would be left to re-bind")
	}
	model, ready, reason, predecessor := readiness()
	if model != "re-bind" || !ready || predecessor != first.Items[0].Fingerprint {
		t.Fatalf("readiness after renewal = %q %v %q predecessor %q, want ready on %q", model, ready, reason, predecessor, first.Items[0].Fingerprint)
	}

	bindsBefore, keysBefore := provider.BindCalls(), provider.UploadedKeys()
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/rollback", tok, map[string]any{
		"identity_id": ident.ID, "reason": "a58 rollback drill",
	})
	if status != http.StatusOK || !jsonContains(t, body, "rollback_queued") || !jsonContains(t, body, "rollback_queued_for_control_plane_execution") ||
		!jsonContains(t, body, "control-plane execution") {
		t.Fatalf("rollback request: status %d body %s", status, body)
	}
	if provider.BindCalls() != bindsBefore {
		t.Fatal("the rollback request handler contacted Certificate Manager; only the outbox worker may")
	}
	var role string
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT required_agent_role FROM outbox WHERE tenant_id=$1 AND destination='connector.rollback' ORDER BY id DESC LIMIT 1`,
			h.tenant).Scan(&role)
	}); err != nil {
		t.Fatalf("read rollback row: %v", err)
	}
	if role != string(connector.VantageControlPlane) {
		t.Fatalf("rollback row required_agent_role = %q, want control_plane so no agent can claim it", role)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain rollback: %v", err)
	}
	if provider.BindCalls() != bindsBefore+1 {
		t.Fatalf("map entry binds after rollback = %d, want %d", provider.BindCalls(), bindsBefore+1)
	}
	if provider.UploadedKeys() != keysBefore {
		t.Fatalf("the rollback uploaded a private key (%d -> %d)", keysBefore, provider.UploadedKeys())
	}
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+firstName) {
		t.Fatalf("map entry after rollback = %v, want the predecessor %q", bound, firstName)
	}
	afterRollback := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	found := false
	for _, item := range afterRollback.Items {
		if item.Destination != "connector.rollback" {
			continue
		}
		if item.Status == "rollback_queued" {
			continue
		}
		found = true
		if item.Status != "rolled_back" || item.Reason != "rolled_back" || item.Fingerprint != first.Items[0].Fingerprint ||
			item.Connector != "gcp-certificate-manager" || item.Target != certID || !strings.Contains(item.Detail, "control plane re-pointed") {
			t.Fatalf("rollback result receipt = %+v", item)
		}
	}
	if !found {
		t.Fatalf("no rollback result receipt was recorded: %s", afterRollback.Raw)
	}
	if !h.hasEvent(t, "connector.rollback.requested") {
		t.Fatal("rollback request did not append connector.rollback.requested")
	}
	// B4-8: the operator's rollback paused automatic renewal of this identity
	// on this target; the identity view says so until an operator resumes it.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+ident.ID, tok, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"renewal_paused":[{"target_id":"`+target.ID+`"`) || !strings.Contains(string(body), "operator rollback: a58 rollback drill") {
		t.Fatalf("identity after an operator rollback: %d %s; want renewal paused on the rolled-back target", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/renewal/resume", tok, "a58-resume", map[string]any{"target_id": target.ID}); status != http.StatusOK || !strings.Contains(string(body), `"renewal_paused":[]`) {
		t.Fatalf("resume after the rollback: %d %s", status, body)
	}
	if pending, err := h.srv.outbox.Pending(t.Context(), h.tenant); err != nil || len(pending) != 0 {
		t.Fatalf("pending outbox after rollback = %d %v", len(pending), err)
	}
}

// A58: families without an executable rollback are refused with the reason
// their API gives, on the route and on the destination's readiness, and a
// GCP target without a certificate map entry is refused at request time
// rather than queued for an executor that would decline it.
func TestServedRollbackRefusalsNameTheProviderReason(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "connectors:read", "connectors:write")
	create := func(name, family string, cfg map[string]any) string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
			"name": name, "connector": family, "config": cfg, "enabled": true,
		})
		if status != http.StatusCreated {
			t.Fatalf("create %s target = %d %s", family, status, body)
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
			t.Fatalf("decode target: %v %s", err, body)
		}
		return created.ID
	}
	readinessReason := func(id string) (string, string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/targets/"+id, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("get target = %d %s", status, body)
		}
		var out struct {
			RollbackReadiness struct {
				Model  string `json:"model"`
				Reason string `json:"reason"`
			} `json:"rollback_readiness"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out.RollbackReadiness.Model, out.RollbackReadiness.Reason
	}
	rollback := func(id string) (int, []byte) {
		t.Helper()
		return secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets/"+id+"/rollback", tok, map[string]any{"reason": "a58 refusal check"})
	}
	acm := create("arn:aws:acm:us-east-1:123456789012:certificate/a58", "aws-acm", map[string]any{
		"region": "us-east-1", "access_key_id": "AKIDA58", "secret_access_key_ref": "secret://connectors/aws-acm/a58",
	})
	if model, reason := readinessReason(acm); model != "none" || !strings.Contains(reason, "keeps no previous version") {
		t.Fatalf("aws-acm readiness = %q %q", model, reason)
	}
	if status, body := rollback(acm); status != http.StatusConflict || !jsonContains(t, body, "no executable rollback route") || !jsonContains(t, body, "keeps no previous version") {
		t.Fatalf("aws-acm rollback = %d %s", status, body)
	}
	akv := create("a58-vault", "azure-keyvault", map[string]any{"endpoint": "https://a58.vault.azure.net", "bearer_token_ref": "secret://connectors/akv/a58"})
	if model, reason := readinessReason(akv); model != "none" || !strings.Contains(reason, "serves the newest") {
		t.Fatalf("azure-keyvault readiness = %q %q", model, reason)
	}
	if status, body := rollback(akv); status != http.StatusConflict || !jsonContains(t, body, "serves the newest") {
		t.Fatalf("azure-keyvault rollback = %d %s", status, body)
	}
	cisco := create("a58-ios", "cisco", map[string]any{"endpoint": "https://ios.example.test", "username": "trstctl", "password_ref": "secret://connectors/ios"})
	if model, reason := readinessReason(cisco); model != "none" || !strings.Contains(reason, "uploads and installs the credential together") {
		t.Fatalf("cisco readiness = %q %q", model, reason)
	}
	plain := create("a58-plain", "gcp-certificate-manager", map[string]any{
		"project": "a58", "location": "global", "bearer_token_ref": "secret://connectors/gcp/a58",
	})
	if model, reason := readinessReason(plain); model != "re-bind" || !strings.Contains(reason, "names no certificate_map_entry") {
		t.Fatalf("gcp target without a map entry readiness = %q %q", model, reason)
	}
	if status, body := rollback(plain); status != http.StatusConflict || !jsonContains(t, body, "names no certificate_map_entry") || jsonContains(t, body, "rollback_queued") {
		t.Fatalf("gcp target without a map entry rollback = %d %s", status, body)
	}
}
