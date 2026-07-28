// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/base64"
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
	servedGCPFederatedTargetID   = "gcp-federated"
	servedGCPFederatedProofName  = "sync/gcp-workload-proof"
	servedGCPFederatedSecretName = "sync/gcp-source"
	servedGCPFederatedSubject    = "system:serviceaccount:default:web"
	servedGCPServiceAccount      = "sync@example.iam.gserviceaccount.com"
)

func TestServedGCPFederatedOutboxTenantIsolationTokenRedaction(t *testing.T) {
	fixture := newGCPFederatedSecretSyncFixture(t)
	trust := servedDynamicK8sTrustFixture(t, "gcp-wif-k1")
	h := newGCPFederatedServedHarness(t, fixture, nil)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "gcp-wif-admin",
		"secrets:read", "secrets:write", "certs:read", "certs:issue")
	sourceID := configureServedGCPFederatedSource(t, h, token, trust)

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs",
		token, "gcp-wif-outbox-operation", map[string]any{
			"name": servedGCPFederatedSecretName, "target": servedGCPFederatedTargetID,
			"remote_key": "prod/payments/db-password",
		})
	if status != http.StatusOK {
		t.Fatalf("queue federated GCP sync: status=%d body=%s", status, body)
	}
	if fixture.stsCalls.Load() != 0 || fixture.impersonationCalls.Load() != 0 ||
		fixture.secretManagerCalls.Load() != 0 {
		t.Fatalf("request path performed egress: sts=%d impersonation=%d secretmanager=%d",
			fixture.stsCalls.Load(), fixture.impersonationCalls.Load(), fixture.secretManagerCalls.Load())
	}

	drainCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	err := h.srv.Drain(drainCtx)
	cancel()
	if err != nil {
		t.Fatalf("drain federated GCP sync: %v", err)
	}
	if fixture.stsCalls.Load() != 1 || fixture.impersonationCalls.Load() != 1 ||
		fixture.secretManagerCalls.Load() != 4 {
		t.Fatalf("outbox delivery calls: sts=%d impersonation=%d secretmanager=%d, want 1/1/4",
			fixture.stsCalls.Load(), fixture.impersonationCalls.Load(), fixture.secretManagerCalls.Load())
	}
	if got := fixture.value(); got != "gcp-federated-sync-value" {
		t.Fatalf("GCP destination readback = %q", got)
	}
	job, err := h.store.GetSecretSyncJob(t.Context(), h.tenant,
		store.DurableSecretSyncJobID(h.tenant, "gcp-wif-outbox-operation"))
	if err != nil || job.Status != store.SecretSyncJobDelivered || job.Attempts != 1 {
		t.Fatalf("federated sync job = %+v err=%v", job, err)
	}
	source, err := h.store.GetSecretSyncWorkloadIdentitySource(t.Context(), h.tenant, sourceID)
	if err != nil || source.Status != store.SecretSyncWorkloadIdentityActive ||
		source.StatusReason != "credential_exchanged" || source.TokenExpiresAt == nil ||
		source.Provider != "gcp" || source.ServiceAccount != servedGCPServiceAccount {
		t.Fatalf("federated source status = %+v err=%v", source, err)
	}

	const tenantB = "22222222-2222-2222-2222-222222222222"
	if _, err := h.store.CreateOwner(t.Context(), store.Owner{
		TenantID: tenantB, Kind: store.OwnerWorkload, Name: "tenant-b-gcp-bootstrap",
	}); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	tenantBToken := seedScopedToken(t, h.store, tenantB, "secrets:read")
	status, body = secretsReq(t, h, http.MethodGet,
		"/api/v1/secrets/syncs/workload-identity-sources/"+sourceID, tenantBToken, nil)
	if status != http.StatusNotFound || strings.Contains(string(body), sourceID) {
		t.Fatalf("cross-tenant GCP workload identity read status=%d body=%s", status, body)
	}

	for _, forbidden := range []string{
		trust.SAT, "gcp-sts-token", "gcp-impersonated-token",
	} {
		if strings.Contains(string(body), forbidden) || h.logContains(t, forbidden) {
			t.Fatalf("authority-bearing GCP federation material reached a response or event log")
		}
		var persisted int
		if err := h.store.SystemPool().QueryRow(t.Context(),
			`SELECT
			    (SELECT count(*) FROM outbox WHERE encode(payload, 'escape') LIKE '%' || $1 || '%') +
			    (SELECT count(*) FROM secret_sync_jobs WHERE last_error LIKE '%' || $1 || '%') +
			    (SELECT count(*) FROM secret_sync_workload_identity_sources
			      WHERE status_reason LIKE '%' || $1 || '%')`,
			forbidden).Scan(&persisted); err != nil {
			t.Fatalf("scan durable GCP token redaction: %v", err)
		}
		if persisted != 0 {
			t.Fatalf("authority-bearing GCP federation material persisted in %d durable rows", persisted)
		}
	}
}

func TestServedGCPFederatedAirGapIsTerminalWithoutNetwork(t *testing.T) {
	fixture := newGCPFederatedSecretSyncFixture(t)
	guard, err := egress.NewGuard(egress.Config{Enabled: true, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	trust := servedDynamicK8sTrustFixture(t, "gcp-wif-airgap-k1")
	h := newGCPFederatedServedHarness(t, fixture, guard)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "gcp-wif-airgap-admin",
		"secrets:read", "secrets:write", "certs:read", "certs:issue")
	sourceID := configureServedGCPFederatedSource(t, h, token, trust)

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs",
		token, "gcp-wif-airgap-operation", map[string]any{
			"name": servedGCPFederatedSecretName, "target": servedGCPFederatedTargetID,
			"remote_key": "prod/payments/db-password",
		})
	if status != http.StatusOK {
		t.Fatalf("queue air-gap federated GCP sync: status=%d body=%s", status, body)
	}
	drainCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	err = h.srv.Drain(drainCtx)
	cancel()
	if err != nil {
		t.Fatalf("drain air-gap federated GCP sync: %v", err)
	}
	if fixture.stsCalls.Load() != 0 || fixture.impersonationCalls.Load() != 0 ||
		fixture.secretManagerCalls.Load() != 0 || guard.Trips() != 0 {
		t.Fatalf("air-gap path reached network: sts=%d impersonation=%d secretmanager=%d trips=%d",
			fixture.stsCalls.Load(), fixture.impersonationCalls.Load(),
			fixture.secretManagerCalls.Load(), guard.Trips())
	}
	job, err := h.store.GetSecretSyncJob(t.Context(), h.tenant,
		store.DurableSecretSyncJobID(h.tenant, "gcp-wif-airgap-operation"))
	if err != nil || job.Status != store.SecretSyncJobFailed || job.Attempts != 1 ||
		job.LastError != "GCP workload identity disabled by air-gap policy" {
		t.Fatalf("air-gap sync job = %+v err=%v", job, err)
	}
	source, err := h.store.GetSecretSyncWorkloadIdentitySource(t.Context(), h.tenant, sourceID)
	if err != nil || source.Status != store.SecretSyncWorkloadIdentityOfflineDisabled ||
		source.StatusReason != "air_gap_enabled" || source.LastFailureAt == nil {
		t.Fatalf("air-gap source status = %+v err=%v", source, err)
	}

	drainCtx, cancel = context.WithTimeout(t.Context(), 10*time.Second)
	err = h.srv.Drain(drainCtx)
	cancel()
	if err != nil || fixture.stsCalls.Load() != 0 || fixture.secretManagerCalls.Load() != 0 {
		t.Fatalf("second air-gap drain retried egress: err=%v sts=%d secretmanager=%d",
			err, fixture.stsCalls.Load(), fixture.secretManagerCalls.Load())
	}
}

func newGCPFederatedServedHarness(t *testing.T, fixture *gcpFederatedSecretSyncFixture, guard *egress.Guard) *servedHarness {
	t.Helper()
	return newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.EgressGuard = guard
			registry, minter, err := secretSyncTargetsFromConfig(context.Background(),
				[]config.SecretSyncTargetConfig{{
					TenantID: servedTestTenant, ID: servedGCPFederatedTargetID,
					Type: "gcp-secret-manager", Endpoint: fixture.server.URL,
					Project: "payments-production", GCPWorkloadIdentity: true,
					WorkloadIdentityEndpoint:              fixture.server.URL + "/v1/token",
					WorkloadIdentityImpersonationEndpoint: fixture.server.URL + "/v1/projects/-/serviceAccounts/" + servedGCPServiceAccount + ":generateAccessToken",
					AllowInsecureLoopback:                 true,
				}},
				d.Store, d.KEK, d.EgressGuard, d.Log)
			if err != nil {
				t.Fatalf("assemble GCP workload identity target: %v", err)
			}
			t.Cleanup(minter.Close)
			d.TenantSecretSyncTargets = registry
			d.CloudTokenMinter = minter
		},
	)
}

func configureServedGCPFederatedSource(t *testing.T, h *servedHarness, token string, trust servedDynamicK8sTrust) string {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]any{"name": servedGCPFederatedProofName, "value": trust.SAT})
	if status != http.StatusCreated {
		t.Fatalf("store GCP workload proof: status=%d body=%s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]any{"name": servedGCPFederatedSecretName, "value": "gcp-federated-sync-value"})
	if status != http.StatusCreated {
		t.Fatalf("store GCP sync source: status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		token, "gcp-wif-trust-source", map[string]any{
			"name": "gcp-wif-kubernetes", "method": "k8s_sat",
			"issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": trust.JWKS,
		})
	if status != http.StatusCreated {
		t.Fatalf("create GCP workload trust source: status=%d body=%s", status, body)
	}
	var trustResponse struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &trustResponse); err != nil || trustResponse.ID == "" {
		t.Fatalf("decode GCP trust source: err=%v body=%s", err, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/syncs/workload-identity-sources",
		token, "gcp-wif-source", map[string]any{
			"name": "payments GCP federation", "provider": "gcp",
			"service_account": servedGCPServiceAccount,
			"audience":        "trstctl", "subject": servedGCPFederatedSubject,
			"target_id":                   servedGCPFederatedTargetID,
			"allowed_remote_key_prefixes": []string{"prod/payments/"},
			"workload_proof_ref":          "secret://" + servedGCPFederatedProofName,
			"trust_source_id":             trustResponse.ID,
		})
	if status != http.StatusCreated {
		t.Fatalf("create GCP workload identity source: status=%d body=%s", status, body)
	}
	if strings.Contains(string(body), trust.SAT) {
		t.Fatalf("GCP workload identity response leaked proof: %s", body)
	}
	var source struct {
		ID             string `json:"id"`
		Provider       string `json:"provider"`
		ServiceAccount string `json:"service_account"`
		Status         string `json:"status"`
	}
	if err := json.Unmarshal(body, &source); err != nil || source.ID == "" ||
		source.Provider != "gcp" || source.ServiceAccount != servedGCPServiceAccount ||
		source.Status != "ready" {
		t.Fatalf("decode GCP workload identity source: err=%v source=%+v body=%s", err, source, body)
	}
	return source.ID
}

type gcpFederatedSecretSyncFixture struct {
	server             *httptest.Server
	stsCalls           atomic.Int32
	impersonationCalls atomic.Int32
	secretManagerCalls atomic.Int32
	mu                 sync.Mutex
	secretCreated      bool
	secretValue        string
}

func newGCPFederatedSecretSyncFixture(t *testing.T) *gcpFederatedSecretSyncFixture {
	t.Helper()
	fixture := &gcpFederatedSecretSyncFixture{}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.handle))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *gcpFederatedSecretSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/token":
		f.handleSTS(w, r)
	case strings.HasSuffix(r.URL.Path, ":generateAccessToken"):
		f.handleImpersonation(w, r)
	default:
		f.handleSecretManager(w, r)
	}
}

func (f *gcpFederatedSecretSyncFixture) handleSTS(w http.ResponseWriter, r *http.Request) {
	f.stsCalls.Add(1)
	raw, _ := io.ReadAll(r.Body)
	values, err := url.ParseQuery(string(raw))
	if err != nil || values.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
		values.Get("subject_token") == "" || values.Get("audience") != "trstctl" {
		http.Error(w, "invalid GCP STS request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"gcp-sts-token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900}`))
}

func (f *gcpFederatedSecretSyncFixture) handleImpersonation(w http.ResponseWriter, r *http.Request) {
	f.impersonationCalls.Add(1)
	if r.Header.Get("Authorization") != "Bearer gcp-sts-token" {
		http.Error(w, "missing GCP STS bearer token", http.StatusUnauthorized)
		return
	}
	expires := time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"accessToken":"gcp-impersonated-token","expireTime":"` + expires + `"}`))
}

func (f *gcpFederatedSecretSyncFixture) handleSecretManager(w http.ResponseWriter, r *http.Request) {
	f.secretManagerCalls.Add(1)
	if r.Header.Get("Authorization") != "Bearer gcp-impersonated-token" {
		http.Error(w, "missing impersonated GCP bearer token", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/versions/latest:access"):
		if f.secretValue == "" {
			http.NotFound(w, r)
			return
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(f.secretValue))
		_, _ = w.Write([]byte(`{"payload":{"data":"` + encoded + `"}}`))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, ":addVersion"):
		if !f.secretCreated {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Payload struct {
				Data string `json:"data"`
			} `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid GCP secret payload", http.StatusBadRequest)
			return
		}
		value, err := base64.StdEncoding.DecodeString(body.Payload.Data)
		if err != nil {
			http.Error(w, "invalid GCP secret bytes", http.StatusBadRequest)
			return
		}
		f.secretValue = string(value)
		_, _ = w.Write([]byte(`{"name":"projects/payments-production/secrets/db-password/versions/1"}`))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secrets"):
		f.secretCreated = true
		_, _ = w.Write([]byte(`{"name":"projects/payments-production/secrets/db-password"}`))
	default:
		http.NotFound(w, r)
	}
}

func (f *gcpFederatedSecretSyncFixture) value() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.secretValue
}
