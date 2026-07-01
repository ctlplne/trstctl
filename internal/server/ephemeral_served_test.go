package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
)

// TestServedEphemeralJITIssuesAfterAttestationAndApproval is the NHI-04
// acceptance proof. It drives the assembled HTTP API: a workload presents a valid
// attestation, the served path opens a dual-control approval request and enqueues
// the notification intent through outbox, a distinct approver authorizes it, and
// a fresh idempotent issue call returns a short-TTL signer-backed credential.
func TestServedEphemeralJITIssuesAfterAttestationAndApproval(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EphemeralIssuance = EphemeralIssuanceConfig{
			Enabled:           true,
			TrustDomain:       "served.test",
			DefaultTTL:        2 * time.Second,
			MaxTTL:            5 * time.Second,
			ApprovalTTL:       time.Minute,
			RequiredApprovals: 1,
			Attestors:         []attest.Attestor{servedEphemeralAttestor{}},
		}
	})
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "jit-requester", "certs:request", "certs:read")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "jit-approver", "certs:issue", "certs:read")
	publicKeyPEM := servedAttestedPublicKeyPEM(t)
	body := map[string]any{
		"request_id":     "jit-agent-7",
		"method":         "stub_ephemeral",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"public_key_pem": publicKeyPEM,
		"ttl_seconds":    2,
	}

	pending := servedEphemeralIssue(t, h, requester, "nhi-04-request", body, http.StatusAccepted)
	if pending.State != "awaiting_approval" || pending.RequestID != "jit-agent-7" || pending.RequiredApprovals != 1 {
		t.Fatalf("pending JIT response = %+v", pending)
	}
	if pending.CertificatePEM != "" || pending.ExpiresAt.IsZero() || !pending.ExpiresAt.After(time.Now()) {
		t.Fatalf("pending JIT response leaked credential or has no approval expiry: %+v", pending)
	}
	if got := ephemeralApprovalOutboxCount(t, h, "ephemeral-approval:jit-agent-7"); got != 1 {
		t.Fatalf("approval outbox rows = %d, want 1", got)
	}

	replayPending := servedEphemeralIssue(t, h, requester, "nhi-04-request", body, http.StatusAccepted)
	if replayPending.RequestID != pending.RequestID || !replayPending.ExpiresAt.Equal(pending.ExpiresAt) {
		t.Fatalf("idempotent pending replay changed: first=%+v replay=%+v", pending, replayPending)
	}

	approval := servedEphemeralApprove(t, h, approver, "nhi-04-approve", "jit-agent-7", http.StatusOK)
	if approval.Resource != "jit-agent-7" || approval.Action != "issue" || approval.Approvals != 1 {
		t.Fatalf("approval response = %+v", approval)
	}

	issued := servedEphemeralIssue(t, h, requester, "nhi-04-issue", body, http.StatusCreated)
	if issued.State != "issued" || issued.CredentialID == "" || issued.CertificateID == "" || issued.CertificatePEM == "" {
		t.Fatalf("issued JIT response = %+v", issued)
	}
	if issued.Subject != "jit-agent-7" || issued.Attestation.Method != "stub_ephemeral" {
		t.Fatalf("issued JIT attestation = %+v", issued)
	}
	if issued.NotAfter.IsZero() || issued.NotAfter.After(time.Now().Add(6*time.Second)) {
		t.Fatalf("short TTL was not enforced; not_after=%s", issued.NotAfter)
	}

	replayIssued := servedEphemeralIssue(t, h, requester, "nhi-04-issue", body, http.StatusCreated)
	if replayIssued.CertificatePEM != issued.CertificatePEM || replayIssued.CredentialID != issued.CredentialID {
		t.Fatalf("idempotent issued replay changed: first=%+v replay=%+v", issued, replayIssued)
	}

	for _, eventType := range []string{"attestation.verified", "attestation.bound", "ephemeral.approval.requested", "ephemeral.approval.granted", "ephemeral.issued", "certificate.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("served ephemeral JIT did not emit %s", eventType)
		}
	}
}

// TestServedEphemeralAPIKeyAutoExpires is the SEC-10 acceptance proof: the
// assembled server exposes ephemeral API-key issuance over the authenticated HTTP
// API, returns the raw token once, authenticates with it immediately, and then the
// served leaseworker records automatic expiry as api_token.revoked so the bearer
// token stops working and metadata shows revocation evidence.
func TestServedEphemeralAPIKeyAutoExpires(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.DynamicLeaseWorkerInterval = 10 * time.Millisecond
	})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "ephemeral-key-admin", "access:read", "access:write")

	worker, ok := any(h.srv).(interface{ RunDynamicLeaseWorker(context.Context) })
	if !ok {
		t.Fatal("served lease worker is not wired")
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		worker.RunDynamicLeaseWorker(workerCtx)
	}()
	t.Cleanup(func() {
		cancelWorker()
		<-workerDone
	})

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/api-keys", admin, "sec10-issue-api-key", map[string]any{
		"subject":     "ci-ephemeral-key",
		"scopes":      []string{"access:read"},
		"ttl_seconds": 1,
	})
	if status != http.StatusCreated {
		t.Fatalf("ephemeral API-key issue status = %d, want 201; body=%s", status, body)
	}
	var issued struct {
		ID        string     `json:"id"`
		Subject   string     `json:"subject"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
		Token     string     `json:"token"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("decode ephemeral API-key response: %v; body=%s", err, body)
	}
	if issued.ID == "" || issued.Subject != "ci-ephemeral-key" || issued.ExpiresAt == nil || !strings.HasPrefix(issued.Token, auth.TokenPrefix) {
		t.Fatalf("ephemeral API-key response = %+v", issued)
	}
	if issued.ExpiresAt.After(time.Now().Add(2 * time.Second)) {
		t.Fatalf("ephemeral API-key expiry = %s, want short TTL", issued.ExpiresAt)
	}
	if h.logContains(t, issued.Token) {
		t.Fatal("ephemeral API-key raw token reached the event log")
	}

	code, roleBody := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", issued.Token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("fresh ephemeral API key role read = %d, want 200; body=%s", code, roleBody)
	}

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		code, _ = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", issued.Token, "", nil)
		metaCode, listed := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/api-tokens?subject=ci-ephemeral-key&include_revoked=true", admin, "", nil)
		if code == http.StatusUnauthorized && metaCode == http.StatusOK && bytes.Contains(listed, []byte(`"revoked_at"`)) {
			if !h.hasEvent(t, "api_token.revoked") {
				t.Fatal("ephemeral API-key expiry did not emit api_token.revoked")
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	code, roleBody = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", issued.Token, "", nil)
	metaCode, listed := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/api-tokens?subject=ci-ephemeral-key&include_revoked=true", admin, "", nil)
	t.Fatalf("ephemeral API key did not auto-expire: roles=%d body=%s metadata=%d body=%s", code, roleBody, metaCode, listed)
}

type servedEphemeralAttestor struct{}

func (servedEphemeralAttestor) Method() string { return "stub_ephemeral" }

func (servedEphemeralAttestor) Attest(_ context.Context, p []byte) (attest.Attestation, error) {
	if string(p) != "genuine" {
		return attest.Attestation{}, errServedEphemeralForgery
	}
	return attest.Attestation{
		Method:    "stub_ephemeral",
		Subject:   "jit-agent-7",
		Selectors: []string{"jit:test"},
	}, nil
}

var errServedEphemeralForgery = errors.New("forged ephemeral proof")

type servedEphemeralResponse struct {
	State             string             `json:"state"`
	RequestID         string             `json:"request_id"`
	Subject           string             `json:"subject"`
	CredentialID      string             `json:"credential_id"`
	CertificateID     string             `json:"certificate_id"`
	CertificatePEM    string             `json:"certificate_pem"`
	RequiredApprovals int                `json:"required_approvals"`
	Approvals         int                `json:"approvals"`
	ExpiresAt         time.Time          `json:"expires_at"`
	NotAfter          time.Time          `json:"not_after"`
	Attestation       attest.Attestation `json:"attestation"`
}

type servedEphemeralApprovalResponse struct {
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Approver  string `json:"approver"`
	Approvals int    `json:"approvals"`
}

func servedEphemeralIssue(t *testing.T, h *servedHarness, token, idemKey string, req map[string]any, want int) servedEphemeralResponse {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral", token, idemKey, req)
	if status != want {
		t.Fatalf("ephemeral issue status = %d, want %d; body=%s", status, want, body)
	}
	var out servedEphemeralResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode ephemeral response: %v; body=%s", err, body)
	}
	return out
}

func servedEphemeralApprove(t *testing.T, h *servedHarness, token, idemKey, requestID string, want int) servedEphemeralApprovalResponse {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/"+requestID+"/approvals", token, idemKey, map[string]any{"action": "issue"})
	if status != want {
		t.Fatalf("ephemeral approve status = %d, want %d; body=%s", status, want, body)
	}
	var out servedEphemeralApprovalResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode ephemeral approval response: %v; body=%s", err, body)
	}
	return out
}

func ephemeralApprovalOutboxCount(t *testing.T, h *servedHarness, key string) int {
	t.Helper()
	var count int
	err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `
			SELECT count(*)
			FROM outbox
			WHERE destination = 'ephemeral.approval'
			  AND idempotency_key = $1
		`, key).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count ephemeral.approval outbox rows: %v", err)
	}
	return count
}

func seedScopedTokenSubject(t *testing.T, st *store.Store, tenant, subject string, scopes ...string) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if _, err := st.CreateAPIToken(context.Background(), store.APITokenRecord{
		TenantID: tenant, TokenHash: hash, Subject: subject, Scopes: scopes,
	}); err != nil {
		t.Fatalf("seed api token: %v", err)
	}
	token := secrettext.String(raw)
	secret.Wipe(raw)
	return token
}
