// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/store"
)

const (
	servedAzureFederatedTargetID   = "azure-federated"
	servedAzureFederatedProofName  = "sync/azure-workload-proof"
	servedAzureFederatedSecretName = "sync/azure-source" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	servedAzureFederatedSubject    = "system:serviceaccount:default:web"
	servedAzureTenantID            = "33333333-3333-4333-8333-333333333333"
	servedAzureClientID            = "44444444-4444-4444-8444-444444444444"
	servedAzureTargetScope         = "https://vault.azure.net/.default"
)

func TestServedAzureFederatedOutboxTenantIsolationTokenRedaction(t *testing.T) {
	fixture := newAzureFederatedSecretSyncFixture(t)
	trust := servedDynamicK8sTrustFixture(t, "azure-wif-k1")
	h := newAzureFederatedServedHarness(t, fixture, nil)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "azure-wif-admin",
		"secrets:read", "secrets:write", "certs:read", "certs:issue")
	sourceID := configureServedAzureFederatedSource(t, h, token, trust)

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs",
		token, "azure-wif-outbox-operation", map[string]any{
			"name": servedAzureFederatedSecretName, "target": servedAzureFederatedTargetID,
			"remote_key": "prod/payments/db-password",
		})
	if status != http.StatusOK {
		t.Fatalf("queue federated Azure sync: status=%d body=%s", status, body)
	}
	if fixture.tokenCalls.Load() != 0 || fixture.vaultCalls.Load() != 0 {
		t.Fatalf("request path performed egress: token=%d vault=%d",
			fixture.tokenCalls.Load(), fixture.vaultCalls.Load())
	}

	drainCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	err := h.srv.Drain(drainCtx)
	cancel()
	if err != nil {
		t.Fatalf("drain federated Azure sync: %v", err)
	}
	if fixture.tokenCalls.Load() != 1 || fixture.vaultCalls.Load() != 2 {
		t.Fatalf("outbox delivery calls: token=%d vault=%d, want 1/2",
			fixture.tokenCalls.Load(), fixture.vaultCalls.Load())
	}
	if got := fixture.value(); got != "azure-federated-sync-value" {
		t.Fatalf("Azure destination readback = %q", got)
	}
	job, err := h.store.GetSecretSyncJob(t.Context(), h.tenant,
		store.DurableSecretSyncJobID(h.tenant, "azure-wif-outbox-operation"))
	if err != nil || job.Status != store.SecretSyncJobDelivered || job.Attempts != 1 {
		t.Fatalf("federated Azure sync job = %+v err=%v", job, err)
	}
	source, err := h.store.GetSecretSyncWorkloadIdentitySource(t.Context(), h.tenant, sourceID)
	if err != nil || source.Status != store.SecretSyncWorkloadIdentityActive ||
		source.StatusReason != "credential_exchanged" || source.TokenExpiresAt == nil ||
		source.Provider != "azure" || source.AzureTenantID != servedAzureTenantID ||
		source.ClientID != servedAzureClientID || source.TargetScope != servedAzureTargetScope {
		t.Fatalf("federated Azure source status = %+v err=%v", source, err)
	}

	const tenantB = "22222222-2222-2222-2222-222222222222"
	if _, err := h.store.CreateOwner(t.Context(), store.Owner{
		TenantID: tenantB, Kind: store.OwnerWorkload, Name: "tenant-b-azure-bootstrap",
	}); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	tenantBToken := seedScopedToken(t, h.store, tenantB, "secrets:read")
	status, body = secretsReq(t, h, http.MethodGet,
		"/api/v1/secrets/syncs/workload-identity-sources/"+sourceID, tenantBToken, nil)
	if status != http.StatusNotFound || strings.Contains(string(body), sourceID) {
		t.Fatalf("cross-tenant Azure workload identity read status=%d body=%s", status, body)
	}

	for _, forbidden := range []string{trust.SAT, "azure-federated-token"} {
		if strings.Contains(string(body), forbidden) || h.logContains(t, forbidden) {
			t.Fatalf("authority-bearing Azure federation material reached a response or event log")
		}
		var persisted int
		if err := h.store.SystemPool().QueryRow(t.Context(),
			`SELECT
			    (SELECT count(*) FROM outbox WHERE encode(payload, 'escape') LIKE '%' || $1 || '%') +
			    (SELECT count(*) FROM secret_sync_jobs WHERE last_error LIKE '%' || $1 || '%') +
			    (SELECT count(*) FROM secret_sync_workload_identity_sources
			      WHERE status_reason LIKE '%' || $1 || '%')`,
			forbidden).Scan(&persisted); err != nil {
			t.Fatalf("scan durable Azure token redaction: %v", err)
		}
		if persisted != 0 {
			t.Fatalf("authority-bearing Azure federation material persisted in %d durable rows", persisted)
		}
	}
}

func TestServedAzureFederatedAirGapIsTerminalWithoutNetwork(t *testing.T) {
	fixture := newAzureFederatedSecretSyncFixture(t)
	guard, err := egress.NewGuard(egress.Config{Enabled: true, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	trust := servedDynamicK8sTrustFixture(t, "azure-wif-airgap-k1")
	h := newAzureFederatedServedHarness(t, fixture, guard)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "azure-wif-airgap-admin",
		"secrets:read", "secrets:write", "certs:read", "certs:issue")
	sourceID := configureServedAzureFederatedSource(t, h, token, trust)

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs",
		token, "azure-wif-airgap-operation", map[string]any{
			"name": servedAzureFederatedSecretName, "target": servedAzureFederatedTargetID,
			"remote_key": "prod/payments/db-password",
		})
	if status != http.StatusOK {
		t.Fatalf("queue air-gap federated Azure sync: status=%d body=%s", status, body)
	}
	drainCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	err = h.srv.Drain(drainCtx)
	cancel()
	if err != nil {
		t.Fatalf("drain air-gap federated Azure sync: %v", err)
	}
	if fixture.tokenCalls.Load() != 0 || fixture.vaultCalls.Load() != 0 || guard.Trips() != 0 {
		t.Fatalf("air-gap path reached network: token=%d vault=%d trips=%d",
			fixture.tokenCalls.Load(), fixture.vaultCalls.Load(), guard.Trips())
	}
	job, err := h.store.GetSecretSyncJob(t.Context(), h.tenant,
		store.DurableSecretSyncJobID(h.tenant, "azure-wif-airgap-operation"))
	if err != nil || job.Status != store.SecretSyncJobFailed || job.Attempts != 1 ||
		job.LastError != "Azure workload identity disabled by air-gap policy" {
		t.Fatalf("air-gap Azure sync job = %+v err=%v", job, err)
	}
	source, err := h.store.GetSecretSyncWorkloadIdentitySource(t.Context(), h.tenant, sourceID)
	if err != nil || source.Status != store.SecretSyncWorkloadIdentityOfflineDisabled ||
		source.StatusReason != "air_gap_enabled" || source.LastFailureAt == nil {
		t.Fatalf("air-gap Azure source status = %+v err=%v", source, err)
	}

	drainCtx, cancel = context.WithTimeout(t.Context(), 10*time.Second)
	err = h.srv.Drain(drainCtx)
	cancel()
	if err != nil || fixture.tokenCalls.Load() != 0 || fixture.vaultCalls.Load() != 0 {
		t.Fatalf("second air-gap drain retried egress: err=%v token=%d vault=%d",
			err, fixture.tokenCalls.Load(), fixture.vaultCalls.Load())
	}
}

func newAzureFederatedServedHarness(t *testing.T, fixture *azureFederatedSecretSyncFixture, guard *egress.Guard) *servedHarness {
	t.Helper()
	return newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.EgressGuard = guard
			registry, minter, err := secretSyncTargetsFromConfig(context.Background(),
				[]config.SecretSyncTargetConfig{{
					TenantID: servedTestTenant, ID: servedAzureFederatedTargetID,
					Type: "azure-key-vault", Endpoint: fixture.server.URL,
					AzureWorkloadIdentity:    true,
					WorkloadIdentityEndpoint: fixture.server.URL + "/entra-token",
					AllowInsecureLoopback:    true,
				}},
				d.Store, d.KEK, d.EgressGuard, d.Log)
			if err != nil {
				t.Fatalf("assemble Azure workload identity target: %v", err)
			}
			t.Cleanup(minter.Close)
			d.TenantSecretSyncTargets = registry
			d.CloudTokenMinter = minter
		},
	)
}

func configureServedAzureFederatedSource(t *testing.T, h *servedHarness, token string, trust servedDynamicK8sTrust) string {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]any{"name": servedAzureFederatedProofName, "value": trust.SAT})
	if status != http.StatusCreated {
		t.Fatalf("store Azure workload proof: status=%d body=%s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]any{"name": servedAzureFederatedSecretName, "value": "azure-federated-sync-value"})
	if status != http.StatusCreated {
		t.Fatalf("store Azure sync source: status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		token, "azure-wif-trust-source", map[string]any{
			"name": "azure-wif-kubernetes", "method": "k8s_sat",
			"issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": trust.JWKS,
		})
	if status != http.StatusCreated {
		t.Fatalf("create Azure workload trust source: status=%d body=%s", status, body)
	}
	var trustResponse struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &trustResponse); err != nil || trustResponse.ID == "" {
		t.Fatalf("decode Azure trust source: err=%v body=%s", err, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/syncs/workload-identity-sources",
		token, "azure-wif-source", map[string]any{
			"name": "payments Azure federation", "provider": "azure",
			"azure_tenant_id": servedAzureTenantID, "client_id": servedAzureClientID,
			"target_scope": servedAzureTargetScope,
			"audience":     "trstctl", "subject": servedAzureFederatedSubject,
			"target_id":                   servedAzureFederatedTargetID,
			"allowed_remote_key_prefixes": []string{"prod/payments/"},
			"workload_proof_ref":          "secret://" + servedAzureFederatedProofName,
			"trust_source_id":             trustResponse.ID,
		})
	if status != http.StatusCreated {
		t.Fatalf("create Azure workload identity source: status=%d body=%s", status, body)
	}
	if strings.Contains(string(body), trust.SAT) {
		t.Fatalf("Azure workload identity response leaked proof: %s", body)
	}
	var source struct {
		ID            string `json:"id"`
		Provider      string `json:"provider"`
		AzureTenantID string `json:"azure_tenant_id"`
		ClientID      string `json:"client_id"`
		TargetScope   string `json:"target_scope"`
		Status        string `json:"status"`
	}
	if err := json.Unmarshal(body, &source); err != nil || source.ID == "" ||
		source.Provider != "azure" || source.AzureTenantID != servedAzureTenantID ||
		source.ClientID != servedAzureClientID || source.TargetScope != servedAzureTargetScope ||
		source.Status != "ready" {
		t.Fatalf("decode Azure workload identity source: err=%v source=%+v body=%s", err, source, body)
	}
	return source.ID
}

type azureFederatedSecretSyncFixture struct {
	server     *httptest.Server
	tokenCalls atomic.Int32
	vaultCalls atomic.Int32
	mu         sync.Mutex
	secret     []byte
}

func newAzureFederatedSecretSyncFixture(t *testing.T) *azureFederatedSecretSyncFixture {
	t.Helper()
	fixture := &azureFederatedSecretSyncFixture{}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.handle))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *azureFederatedSecretSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/entra-token" {
		f.handleToken(w, r)
		return
	}
	f.handleVault(w, r)
}

func (f *azureFederatedSecretSyncFixture) handleToken(w http.ResponseWriter, r *http.Request) {
	f.tokenCalls.Add(1)
	raw, _ := io.ReadAll(r.Body)
	values, err := url.ParseQuery(string(raw))
	if err != nil ||
		values.Get("grant_type") != "client_credentials" ||
		values.Get("client_id") != servedAzureClientID ||
		values.Get("scope") != servedAzureTargetScope ||
		values.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
		values.Get("client_assertion") == "" {
		http.Error(w, "invalid Entra federated-credential request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"token_type":"Bearer","access_token":"azure-federated-token","expires_in":900}`))
}

func (f *azureFederatedSecretSyncFixture) handleVault(w http.ResponseWriter, r *http.Request) {
	f.vaultCalls.Add(1)
	if r.Header.Get("Authorization") != "Bearer azure-federated-token" {
		http.Error(w, "missing federated Azure bearer token", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		if len(f.secret) == 0 {
			http.NotFound(w, r)
			return
		}
		body, _ := json.Marshal(struct {
			Value []byte `json:"value"`
		}{Value: f.secret})
		_, _ = w.Write(body)
	case http.MethodPut:
		var body struct {
			Value []byte `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Value) == 0 {
			http.Error(w, "invalid Azure secret payload", http.StatusBadRequest)
			return
		}
		f.secret = append(f.secret[:0], body.Value...)
		_, _ = w.Write([]byte(`{"id":"secret-version-1"}`))
	default:
		http.NotFound(w, r)
	}
}

func (f *azureFederatedSecretSyncFixture) value() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.secret)
}
