// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// A214: a target without a verification address gets the address a scan saw
// its delivered leaf at, with the finding as evidence; nothing changes until
// an operator confirms it, an address no finding suggests or a stale revision
// is refused, and the confirmed address is what deployments verify next.
func TestServedVerificationAddressIsSuggestedFromScansAndSetOnlyOnConfirmation(t *testing.T) {
	ctx := t.Context()
	h := newServedHarness(t, config.Protocols{})
	tenant := uuid.NewString()
	registerServedTenantID(t, h, tenant, "A214 verification tenant")
	token := seedScopedToken(t, h.store, tenant, "connectors:read", "connectors:write")
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, tenant, store.DeploymentTarget{
		Name: "a214-web", Type: "nginx", Enabled: true, EnabledSet: true,
		Config: json.RawMessage(`{"cert_path":"/etc/nginx/a214.crt","key_path":"/etc/nginx/a214.key"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("e4", 32)
	now := time.Now().UTC()
	if _, err := h.srv.orch.RecordConnectorDelivery(ctx, tenant, store.ConnectorDeliveryReceipt{
		ID: uuid.NewString(), Destination: "connector.deploy", Connector: "nginx", Target: "a214-web",
		Fingerprint: fingerprint, Status: "delivered", IdempotencyKey: "a214-deliver", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// The sweep that saw the leaf, as a relay's TLS run records it.
	sourceID, runID := uuid.NewString(), uuid.NewString()
	if err := h.store.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := h.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: tenant, Kind: "manual", Name: "a214-sweep", Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		return h.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: tenant, SourceID: sourceID, Status: "running", CreatedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}
	finding, err := h.srv.orch.RecordDiscoveryFinding(ctx, tenant, store.DiscoveryFinding{
		RunID: runID, SourceID: sourceID, Kind: "x509_certificate", Ref: "192.0.2.14:8443",
		Provenance: "tls:a214", Fingerprint: fingerprint, Metadata: []byte(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	type suggestions struct {
		TargetRevision string `json:"target_revision"`
		VerifyAddress  string `json:"verify_address"`
		Suggestions    []struct {
			Address  string `json:"address"`
			Evidence []struct {
				FindingID   string `json:"finding_id"`
				Fingerprint string `json:"fingerprint"`
			} `json:"evidence"`
		} `json:"suggestions"`
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/targets/"+target.ID+"/verification-suggestions", token, nil)
	if status != http.StatusOK {
		t.Fatalf("suggestions = %d %s", status, body)
	}
	var got suggestions
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.VerifyAddress != "" || len(got.Suggestions) != 1 || got.Suggestions[0].Address != "192.0.2.14:8443" ||
		len(got.Suggestions[0].Evidence) != 1 || got.Suggestions[0].Evidence[0].FindingID != finding.ID ||
		got.Suggestions[0].Evidence[0].Fingerprint != fingerprint {
		t.Fatalf("suggestions = %+v; want the scanned address with its finding", got)
	}
	if stored, _ := h.store.GetDeploymentTarget(ctx, tenant, target.ID); verifyAddressOf(stored) != "" {
		t.Fatal("reading suggestions changed the target")
	}

	confirm := func(key, address, revision string) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/verification-address", token, key,
			map[string]any{"address": address, "server_name": "a214.example.test", "target_revision": revision})
	}
	if status, body := confirm("a214-unsuggested", "192.0.2.99:443", got.TargetRevision); status != http.StatusConflict {
		t.Fatalf("an unsuggested address = %d %s; want 409", status, body)
	}
	if status, body := confirm("a214-stale", "192.0.2.14:8443", "stale-revision"); status != http.StatusConflict {
		t.Fatalf("a stale revision = %d %s; want 409", status, body)
	}
	if stored, _ := h.store.GetDeploymentTarget(ctx, tenant, target.ID); verifyAddressOf(stored) != "" {
		t.Fatal("a refused confirmation changed the target")
	}
	status, confirmed := confirm("a214-confirm", "192.0.2.14:8443", got.TargetRevision)
	if status != http.StatusOK {
		t.Fatalf("confirm = %d %s", status, confirmed)
	}
	if status, replay := confirm("a214-confirm", "192.0.2.14:8443", got.TargetRevision); status != http.StatusOK || string(replay) != string(confirmed) {
		t.Fatalf("confirm replay = %d %s; want the same answer", status, replay)
	}
	stored, err := h.store.GetDeploymentTarget(ctx, tenant, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	address, serverName := verifyTargetFromConfig(stored.Config)
	var kept struct {
		CertPath string `json:"cert_path"`
	}
	if err := json.Unmarshal(stored.Config, &kept); err != nil {
		t.Fatal(err)
	}
	if address != "192.0.2.14:8443" || serverName != "a214.example.test" || stored.RevisionID == got.TargetRevision ||
		kept.CertPath != "/etc/nginx/a214.crt" {
		t.Fatalf("confirmed target = %s (revision %s); want the address set, a new revision and the rest kept", stored.Config, stored.RevisionID)
	}
}

func verifyAddressOf(target store.DeploymentTarget) string {
	address, _ := verifyTargetFromConfig(target.Config)
	return address
}
