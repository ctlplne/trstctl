// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	servedAWSFederatedTargetID   = "aws-federated"
	servedAWSFederatedProofName  = "sync/workload-proof"
	servedAWSFederatedSecretName = "sync/source"
	servedAWSFederatedSubject    = "system:serviceaccount:default:web"
)

func TestServedAWSFederatedOutboxTenantIsolationTokenRedaction(t *testing.T) {
	fixture := newAWSFederatedSecretSyncFixture(t)
	trust := servedDynamicK8sTrustFixture(t, "aws-wif-k1")
	h := newAWSFederatedServedHarness(t, fixture, nil)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "aws-wif-admin",
		"secrets:read", "secrets:write", "certs:read", "certs:issue")
	sourceID := configureServedAWSFederatedSource(t, h, token, trust)

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs",
		token, "aws-wif-outbox-operation", map[string]any{
			"name": servedAWSFederatedSecretName, "target": servedAWSFederatedTargetID,
			"remote_key": "prod/payments/db-password",
		})
	if status != http.StatusOK {
		t.Fatalf("queue federated AWS sync: status=%d body=%s", status, body)
	}
	if fixture.stsCalls.Load() != 0 || fixture.secretManagerCalls.Load() != 0 {
		t.Fatalf("request path performed egress: sts=%d secretsmanager=%d",
			fixture.stsCalls.Load(), fixture.secretManagerCalls.Load())
	}

	drainCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	err := h.srv.Drain(drainCtx)
	cancel()
	if err != nil {
		t.Fatalf("drain federated AWS sync: %v", err)
	}
	if fixture.stsCalls.Load() != 1 || fixture.secretManagerCalls.Load() != 1 {
		t.Fatalf("outbox delivery calls: sts=%d secretsmanager=%d, want 1/1",
			fixture.stsCalls.Load(), fixture.secretManagerCalls.Load())
	}
	if got := fixture.value("prod/payments/db-password"); got != "federated-sync-value" {
		t.Fatalf("AWS destination readback = %q", got)
	}
	job, err := h.store.GetSecretSyncJob(t.Context(), h.tenant,
		store.DurableSecretSyncJobID(h.tenant, "aws-wif-outbox-operation"))
	if err != nil || job.Status != store.SecretSyncJobDelivered || job.Attempts != 1 {
		t.Fatalf("federated sync job = %+v err=%v", job, err)
	}
	source, err := h.store.GetSecretSyncWorkloadIdentitySource(t.Context(), h.tenant, sourceID)
	if err != nil || source.Status != store.SecretSyncWorkloadIdentityActive ||
		source.StatusReason != "credential_exchanged" || source.TokenExpiresAt == nil {
		t.Fatalf("federated source status = %+v err=%v", source, err)
	}

	const tenantB = "22222222-2222-2222-2222-222222222222"
	if _, err := h.store.CreateOwner(t.Context(), store.Owner{
		TenantID: tenantB, Kind: store.OwnerWorkload, Name: "tenant-b-bootstrap",
	}); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	tenantBToken := seedScopedToken(t, h.store, tenantB, "secrets:read")
	status, body = secretsReq(t, h, http.MethodGet,
		"/api/v1/secrets/syncs/workload-identity-sources/"+sourceID, tenantBToken, nil)
	if status != http.StatusNotFound || strings.Contains(string(body), sourceID) {
		t.Fatalf("cross-tenant workload identity read status=%d body=%s", status, body)
	}

	for _, forbidden := range []string{
		trust.SAT, "temporary-secret-access-key", "temporary-session-token",
	} {
		if strings.Contains(string(body), forbidden) || h.logContains(t, forbidden) {
			t.Fatalf("authority-bearing AWS federation material reached a response or event log")
		}
		var persisted int
		if err := h.store.SystemPool().QueryRow(t.Context(),
			`SELECT
			    (SELECT count(*) FROM outbox WHERE encode(payload, 'escape') LIKE '%' || $1 || '%') +
			    (SELECT count(*) FROM secret_sync_jobs WHERE last_error LIKE '%' || $1 || '%') +
			    (SELECT count(*) FROM secret_sync_workload_identity_sources
			      WHERE role_arn LIKE '%' || $1 || '%' OR status_reason LIKE '%' || $1 || '%')`,
			forbidden).Scan(&persisted); err != nil {
			t.Fatalf("scan durable token redaction: %v", err)
		}
		if persisted != 0 {
			t.Fatalf("authority-bearing AWS federation material persisted in %d durable rows", persisted)
		}
	}
}

func TestServedAWSFederatedAirGapIsTerminalWithoutNetwork(t *testing.T) {
	fixture := newAWSFederatedSecretSyncFixture(t)
	guard, err := egress.NewGuard(egress.Config{Enabled: true, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	trust := servedDynamicK8sTrustFixture(t, "aws-wif-airgap-k1")
	h := newAWSFederatedServedHarness(t, fixture, guard)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "aws-wif-airgap-admin",
		"secrets:read", "secrets:write", "certs:read", "certs:issue")
	sourceID := configureServedAWSFederatedSource(t, h, token, trust)

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs",
		token, "aws-wif-airgap-operation", map[string]any{
			"name": servedAWSFederatedSecretName, "target": servedAWSFederatedTargetID,
			"remote_key": "prod/payments/db-password",
		})
	if status != http.StatusOK {
		t.Fatalf("queue air-gap federated sync: status=%d body=%s", status, body)
	}
	drainCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	err = h.srv.Drain(drainCtx)
	cancel()
	if err != nil {
		t.Fatalf("drain air-gap federated sync: %v", err)
	}
	if fixture.stsCalls.Load() != 0 || fixture.secretManagerCalls.Load() != 0 || guard.Trips() != 0 {
		t.Fatalf("air-gap path reached network guard/provider: sts=%d secretsmanager=%d trips=%d",
			fixture.stsCalls.Load(), fixture.secretManagerCalls.Load(), guard.Trips())
	}
	job, err := h.store.GetSecretSyncJob(t.Context(), h.tenant,
		store.DurableSecretSyncJobID(h.tenant, "aws-wif-airgap-operation"))
	if err != nil || job.Status != store.SecretSyncJobFailed || job.Attempts != 1 ||
		job.LastError != "AWS workload identity disabled by air-gap policy" {
		t.Fatalf("air-gap sync job = %+v err=%v", job, err)
	}
	source, err := h.store.GetSecretSyncWorkloadIdentitySource(t.Context(), h.tenant, sourceID)
	if err != nil || source.Status != store.SecretSyncWorkloadIdentityOfflineDisabled ||
		source.StatusReason != "air_gap_enabled" || source.LastFailureAt == nil {
		t.Fatalf("air-gap source status = %+v err=%v", source, err)
	}

	// A second drain proves the outbox ACKed the terminal disabled state instead
	// of building an infinite retry loop.
	drainCtx, cancel = context.WithTimeout(t.Context(), 10*time.Second)
	err = h.srv.Drain(drainCtx)
	cancel()
	if err != nil || fixture.stsCalls.Load() != 0 || fixture.secretManagerCalls.Load() != 0 {
		t.Fatalf("second air-gap drain retried egress: err=%v sts=%d secretsmanager=%d",
			err, fixture.stsCalls.Load(), fixture.secretManagerCalls.Load())
	}
}

func newAWSFederatedServedHarness(t *testing.T, fixture *awsFederatedSecretSyncFixture, guard *egress.Guard) *servedHarness {
	t.Helper()
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.EgressGuard = guard
			registry, minter, err := secretSyncTargetsFromConfig(context.Background(),
				[]config.SecretSyncTargetConfig{{
					TenantID: servedTestTenant, ID: servedAWSFederatedTargetID,
					Type: "aws-secrets-manager", Endpoint: fixture.secretManager.URL,
					Region: "us-east-1", AWSWorkloadIdentity: true,
					WorkloadIdentityEndpoint: fixture.sts.URL,
					AllowInsecureLoopback:    true,
				}},
				d.Store, d.KEK, d.EgressGuard, d.Log)
			if err != nil {
				t.Fatalf("assemble AWS workload identity target: %v", err)
			}
			t.Cleanup(minter.Close)
			d.TenantSecretSyncTargets = registry
			d.CloudTokenMinter = minter
		},
	)
	registerServedTenant(t, h, "AWS federated secret-sync tenant")
	return h
}

func configureServedAWSFederatedSource(t *testing.T, h *servedHarness, token string, trust servedDynamicK8sTrust) string {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]any{"name": servedAWSFederatedProofName, "value": trust.SAT})
	if status != http.StatusCreated {
		t.Fatalf("store workload proof: status=%d body=%s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]any{"name": servedAWSFederatedSecretName, "value": "federated-sync-value"})
	if status != http.StatusCreated {
		t.Fatalf("store sync source: status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		token, "aws-wif-trust-source", map[string]any{
			"name": "aws-wif-kubernetes", "method": "k8s_sat",
			"issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": trust.JWKS,
		})
	if status != http.StatusCreated {
		t.Fatalf("create workload trust source: status=%d body=%s", status, body)
	}
	var trustResponse struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &trustResponse); err != nil || trustResponse.ID == "" {
		t.Fatalf("decode trust source: err=%v body=%s", err, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/syncs/workload-identity-sources",
		token, "aws-wif-source", map[string]any{
			"name": "payments AWS federation", "provider": "aws",
			"role_arn": "arn:aws:iam::123456789012:role/trstctl-secret-sync",
			"audience": "trstctl", "subject": servedAWSFederatedSubject,
			"target_id":                   servedAWSFederatedTargetID,
			"allowed_remote_key_prefixes": []string{"prod/payments/"},
			"workload_proof_ref":          "secret://" + servedAWSFederatedProofName,
			"trust_source_id":             trustResponse.ID,
		})
	if status != http.StatusCreated {
		t.Fatalf("create AWS workload identity source: status=%d body=%s", status, body)
	}
	if strings.Contains(string(body), trust.SAT) {
		t.Fatalf("workload identity response leaked proof: %s", body)
	}
	var source struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &source); err != nil || source.ID == "" || source.Status != "ready" {
		t.Fatalf("decode AWS workload identity source: err=%v source=%+v body=%s", err, source, body)
	}
	return source.ID
}

type awsFederatedSecretSyncFixture struct {
	sts                *httptest.Server
	secretManager      *httptest.Server
	stsCalls           atomic.Int32
	secretManagerCalls atomic.Int32
	mu                 sync.Mutex
	values             map[string]string
}

func newAWSFederatedSecretSyncFixture(t *testing.T) *awsFederatedSecretSyncFixture {
	t.Helper()
	fixture := &awsFederatedSecretSyncFixture{values: map[string]string{}}
	fixture.sts = httptest.NewServer(http.HandlerFunc(fixture.handleSTS))
	fixture.secretManager = httptest.NewServer(http.HandlerFunc(fixture.handleSecretManager))
	t.Cleanup(fixture.sts.Close)
	t.Cleanup(fixture.secretManager.Close)
	return fixture
}

func (f *awsFederatedSecretSyncFixture) handleSTS(w http.ResponseWriter, r *http.Request) {
	f.stsCalls.Add(1)
	raw, _ := io.ReadAll(r.Body)
	values, err := url.ParseQuery(string(raw))
	if err != nil || values.Get("Action") != "AssumeRoleWithWebIdentity" ||
		values.Get("RoleArn") != "arn:aws:iam::123456789012:role/trstctl-secret-sync" ||
		!strings.HasPrefix(values.Get("RoleSessionName"), "trstctl-") ||
		values.Get("WebIdentityToken") == "" {
		http.Error(w, "invalid STS request", http.StatusBadRequest)
		return
	}
	expires := time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339)
	w.Header().Set("Content-Type", "text/xml")
	_, _ = fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>`+
		`<AccessKeyId>ASIATEMPORARY</AccessKeyId>`+
		`<SecretAccessKey>temporary-secret-access-key</SecretAccessKey>`+
		`<SessionToken>temporary-session-token</SessionToken>`+
		`<Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, expires)
}

func (f *awsFederatedSecretSyncFixture) handleSecretManager(w http.ResponseWriter, r *http.Request) {
	f.secretManagerCalls.Add(1)
	if !strings.Contains(r.Header.Get("Authorization"), "Credential=ASIATEMPORARY/") ||
		r.Header.Get("X-Amz-Security-Token") != "temporary-session-token" {
		http.Error(w, "missing temporary SigV4 credentials", http.StatusUnauthorized)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var request struct {
		Name         string `json:"Name"`
		SecretBinary string `json:"SecretBinary"`
	}
	if err := json.Unmarshal(raw, &request); err != nil || request.Name == "" {
		http.Error(w, "invalid AWS secret request", http.StatusBadRequest)
		return
	}
	value, err := base64.StdEncoding.DecodeString(request.SecretBinary)
	if err != nil {
		http.Error(w, "invalid secret bytes", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.values[request.Name] = string(value)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:us-east-1:123456789012:secret:test"}`))
}

func (f *awsFederatedSecretSyncFixture) value(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[name]
}
