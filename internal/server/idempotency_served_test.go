// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestServedIssueTransitionBindsOutboxToRequestIdempotencyKey(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant,
		"owners:write",
		"issuers:write",
		"identities:write",
		"identities:read",
		"certs:read",
		"certs:issue",
	)

	ownerID := servedCreateID(t, h, token, "correct-001-owner", "/api/v1/owners",
		map[string]any{"kind": "workload", "name": "correct-001-owner"})
	issuerID := servedCreateID(t, h, token, "correct-001-issuer", "/api/v1/issuers",
		map[string]any{"kind": "x509_ca", "name": "correct-001-issuer", "chain": []string{string(h.caPEM)}, "internal": true})
	identityName := "correct-001.served.test"
	identityID := servedCreateID(t, h, token, "correct-001-identity", "/api/v1/identities",
		map[string]any{"kind": "x509_certificate", "name": identityName, "owner_id": ownerID, "issuer_id": issuerID})

	issueKey := "correct-001-issue-replay"
	status, body := servedMutationRequest(t, h, servedReplayCase{
		name:   "correct-001 issue",
		method: http.MethodPost,
		path:   "/api/v1/identities/" + identityID + "/transitions",
		token:  token,
		key:    issueKey,
		body:   map[string]any{"to": "issued"},
	})
	if status != http.StatusOK {
		t.Fatalf("first issue transition = %d: %s", status, body)
	}

	if got := servedOutboxCount(t, h, "ca.issue", "transition:"+issueKey); got != 1 {
		t.Fatalf("ca.issue rows for request Idempotency-Key = %d, want 1", got)
	}
	if got := servedOutboxDestinationCount(t, h, "ca.issue"); got != 1 {
		t.Fatalf("ca.issue rows after first transition = %d, want 1", got)
	}
	if err := h.srv.Drain(context.Background()); err != nil {
		t.Fatalf("drain first issue: %v", err)
	}
	if got := servedCertificateSubjectCount(t, h, identityName); got != 1 {
		t.Fatalf("certificates for %s after first issue = %d, want 1", identityName, got)
	}

	status, body = servedMutationRequest(t, h, servedReplayCase{
		name:   "correct-001 issue replay",
		method: http.MethodPost,
		path:   "/api/v1/identities/" + identityID + "/transitions",
		token:  token,
		key:    issueKey,
		body:   map[string]any{"to": "issued"},
	})
	if status != http.StatusOK {
		t.Fatalf("replayed issue transition = %d: %s", status, body)
	}
	if err := h.srv.Drain(context.Background()); err != nil {
		t.Fatalf("drain replayed issue: %v", err)
	}
	if got := servedOutboxDestinationCount(t, h, "ca.issue"); got != 1 {
		t.Fatalf("ca.issue rows after replay = %d, want still 1", got)
	}
	if got := servedCertificateSubjectCount(t, h, identityName); got != 1 {
		t.Fatalf("certificates for %s after replay = %d, want still 1", identityName, got)
	}
}

// TestServedMutationIdempotencyReplayMatrix is the ARCH-006 protection guard for
// AN-5 over the live served API composition. It drives representative mutation
// families through server.Build -> Handler on the embedded stack, then retries the
// exact request with the same Idempotency-Key. A correct replay returns the cached
// response and does not append a second tenant event.
func TestServedMutationIdempotencyReplayMatrix(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant,
		"owners:write",
		"issuers:write",
		"identities:write",
		"certs:write",
		"certs:issue",
		"profiles:write",
		"agents:write",
		"secrets:write",
	)

	ownerBody := assertServedMutationReplay(t, h, servedReplayCase{
		name:       "owners create",
		method:     http.MethodPost,
		path:       "/api/v1/owners",
		token:      token,
		key:        "arch-006-owner-create",
		body:       map[string]any{"kind": "workload", "name": "arch-006-owner"},
		wantStatus: http.StatusCreated,
		eventType:  "owner.created",
	})
	var owner struct {
		ID string `json:"id"`
	}
	decodeServedReplayBody(t, ownerBody, &owner)
	if owner.ID == "" {
		t.Fatalf("owners create replay returned no id: %s", ownerBody)
	}

	issuerBody := assertServedMutationReplay(t, h, servedReplayCase{
		name:       "issuers create",
		method:     http.MethodPost,
		path:       "/api/v1/issuers",
		token:      token,
		key:        "arch-006-issuer-create",
		body:       map[string]any{"kind": "x509_ca", "name": "arch-006-issuer", "chain": []string{string(h.caPEM)}, "internal": true},
		wantStatus: http.StatusCreated,
		eventType:  "issuer.created",
	})
	var issuer struct {
		ID string `json:"id"`
	}
	decodeServedReplayBody(t, issuerBody, &issuer)
	if issuer.ID == "" {
		t.Fatalf("issuers create replay returned no id: %s", issuerBody)
	}

	identityBody := assertServedMutationReplay(t, h, servedReplayCase{
		name:       "identities create",
		method:     http.MethodPost,
		path:       "/api/v1/identities",
		token:      token,
		key:        "arch-006-identity-create",
		body:       map[string]any{"kind": "x509_certificate", "name": "arch-006-identity", "owner_id": owner.ID, "issuer_id": issuer.ID},
		wantStatus: http.StatusCreated,
		eventType:  "identity.created",
	})
	var identity struct {
		ID string `json:"id"`
	}
	decodeServedReplayBody(t, identityBody, &identity)
	if identity.ID == "" {
		t.Fatalf("identities create replay returned no id: %s", identityBody)
	}

	assertServedMutationReplay(t, h, servedReplayCase{
		name:       "identity transition",
		method:     http.MethodPost,
		path:       "/api/v1/identities/" + identity.ID + "/transitions",
		token:      token,
		key:        "arch-006-identity-transition",
		body:       map[string]any{"to": "issued", "reason": "ARCH-006 replay guard"},
		wantStatus: http.StatusOK,
		eventType:  "identity.issued",
	})

	assertServedMutationReplay(t, h, servedReplayCase{
		name:       "certificates ingest",
		method:     http.MethodPost,
		path:       "/api/v1/certificates",
		token:      token,
		key:        "arch-006-certificate-ingest",
		body:       map[string]any{"pem": string(h.caPEM), "owner_id": owner.ID, "source": "import", "deployment_location": "arch-006"},
		wantStatus: http.StatusCreated,
		eventType:  "certificate.recorded",
	})

	assertServedMutationReplay(t, h, servedReplayCase{
		name:   "profiles create",
		method: http.MethodPost,
		path:   "/api/v1/profiles",
		token:  token,
		key:    "arch-006-profile-create",
		body: map[string]any{
			"name": "arch-006-profile",
			"spec": map[string]any{
				"subject":         map[string]any{"common_name": "arch-006.example.test"},
				"max_ttl_seconds": 3600,
			},
		},
		wantStatus: http.StatusCreated,
		eventType:  "profile.created",
	})

	assertServedMutationReplay(t, h, servedReplayCase{
		name:       "agent enrollment tokens",
		method:     http.MethodPost,
		path:       "/api/v1/agents/enrollment-tokens",
		token:      token,
		key:        "arch-006-agent-token",
		wantStatus: http.StatusCreated,
	})

	assertServedMutationReplay(t, h, servedReplayCase{
		name:       "secrets create",
		method:     http.MethodPost,
		path:       "/api/v1/secrets/store",
		token:      token,
		key:        "arch-006-secret-create",
		body:       map[string]any{"name": "arch-006/db-password", "value": "secret-value"},
		wantStatus: http.StatusCreated,
		eventType:  "secret.created",
	})
}

func TestServedMutationRequiresIdempotencyKeyHeaderNotWrongHeader(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "owners:write")
	body := map[string]any{"kind": "workload", "name": "arch-002-owner"}

	status, data := servedMutationRequestWithHeaders(t, h, http.MethodPost, "/api/v1/owners", token, nil, body)
	if status != http.StatusBadRequest || !bytes.Contains(data, []byte("Idempotency-Key")) {
		t.Fatalf("owner create without Idempotency-Key = %d %s, want 400 mentioning header", status, data)
	}

	status, data = servedMutationRequestWithHeaders(t, h, http.MethodPost, "/api/v1/owners", token, map[string]string{
		"X-Idempotency-Key": "arch-002-wrong-header",
	}, body)
	if status != http.StatusBadRequest || !bytes.Contains(data, []byte("Idempotency-Key")) {
		t.Fatalf("owner create with wrong idempotency header = %d %s, want 400 mentioning header", status, data)
	}

	before := servedEventCount(t, h, "owner.created")
	headers := map[string]string{"Idempotency-Key": "arch-002-correct-header"}
	firstStatus, firstBody := servedMutationRequestWithHeaders(t, h, http.MethodPost, "/api/v1/owners", token, headers, body)
	secondStatus, secondBody := servedMutationRequestWithHeaders(t, h, http.MethodPost, "/api/v1/owners", token, headers, body)
	if firstStatus != http.StatusCreated {
		t.Fatalf("owner create with Idempotency-Key = %d %s, want 201", firstStatus, firstBody)
	}
	if secondStatus != http.StatusCreated {
		t.Fatalf("owner create replay = %d %s, want 201", secondStatus, secondBody)
	}
	if !bytes.Equal(firstBody, secondBody) {
		t.Fatalf("owner create replay body changed\nfirst:  %s\nsecond: %s", firstBody, secondBody)
	}
	if after := servedEventCount(t, h, "owner.created"); after != before+1 {
		t.Fatalf("owner create replay appended %d events, want exactly 1", after-before)
	}
}

type servedReplayCase struct {
	name       string
	method     string
	path       string
	token      string
	key        string
	body       any
	wantStatus int
	eventType  string
}

func assertServedMutationReplay(t *testing.T, h *servedHarness, tc servedReplayCase) []byte {
	t.Helper()
	before := servedEventCount(t, h, tc.eventType)
	firstStatus, firstBody := servedMutationRequest(t, h, tc)
	secondStatus, secondBody := servedMutationRequest(t, h, tc)

	if firstStatus != tc.wantStatus {
		t.Fatalf("%s first status = %d, want %d; body=%s", tc.name, firstStatus, tc.wantStatus, firstBody)
	}
	if secondStatus != tc.wantStatus {
		t.Fatalf("%s replay status = %d, want %d; body=%s", tc.name, secondStatus, tc.wantStatus, secondBody)
	}
	if !bytes.Equal(firstBody, secondBody) {
		t.Fatalf("%s replay body changed\nfirst:  %s\nsecond: %s", tc.name, firstBody, secondBody)
	}
	if tc.eventType != "" {
		after := servedEventCount(t, h, tc.eventType)
		if after != before+1 {
			t.Fatalf("%s appended %d %q events, want exactly 1", tc.name, after-before, tc.eventType)
		}
	}
	return firstBody
}

func servedMutationRequest(t *testing.T, h *servedHarness, tc servedReplayCase) (int, []byte) {
	t.Helper()
	var body io.Reader
	if tc.body != nil {
		data, err := json.Marshal(tc.body)
		if err != nil {
			t.Fatalf("%s: marshal body: %v", tc.name, err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(tc.method, h.ts.URL+tc.path, body)
	if err != nil {
		t.Fatalf("%s: new request: %v", tc.name, err)
	}
	req.Header.Set("Authorization", "Bearer "+tc.token)
	req.Header.Set("X-Tenant-ID", h.tenant)
	req.Header.Set("Idempotency-Key", tc.key)
	if tc.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s: do request: %v", tc.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: read response: %v", tc.name, err)
	}
	return resp.StatusCode, data
}

func servedMutationRequestWithHeaders(t *testing.T, h *servedHarness, method, path, token string, headers map[string]string, payload any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, h.ts.URL+path, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", h.tenant)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, data
}

func servedEventCount(t *testing.T, h *servedHarness, eventType string) int {
	t.Helper()
	if eventType == "" {
		return 0
	}
	count := 0
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type == eventType && e.TenantID == h.tenant {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	return count
}

func decodeServedReplayBody(t *testing.T, body []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("decode replay body: %v; body=%s", err, body)
	}
}

func servedCreateID(t *testing.T, h *servedHarness, token, key, path string, body any) string {
	t.Helper()
	status, data := servedMutationRequest(t, h, servedReplayCase{
		name:   key,
		method: http.MethodPost,
		path:   path,
		token:  token,
		key:    key,
		body:   body,
	})
	if status != http.StatusCreated {
		t.Fatalf("%s = %d: %s", path, status, data)
	}
	var out struct {
		ID string `json:"id"`
	}
	decodeServedReplayBody(t, data, &out)
	if out.ID == "" {
		t.Fatalf("%s returned no id: %s", path, data)
	}
	return out.ID
}

func servedOutboxCount(t *testing.T, h *servedHarness, destination, idempotencyKey string) int {
	t.Helper()
	var count int
	if err := h.store.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM outbox
		  WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3`,
		h.tenant, destination, idempotencyKey).Scan(&count); err != nil {
		t.Fatalf("count outbox %s/%s: %v", destination, idempotencyKey, err)
	}
	return count
}

func servedOutboxDestinationCount(t *testing.T, h *servedHarness, destination string) int {
	t.Helper()
	var count int
	if err := h.store.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		h.tenant, destination).Scan(&count); err != nil {
		t.Fatalf("count outbox destination %s: %v", destination, err)
	}
	return count
}

func servedCertificateSubjectCount(t *testing.T, h *servedHarness, subject string) int {
	t.Helper()
	var count int
	if err := h.store.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM certificates WHERE tenant_id = $1 AND subject LIKE '%' || $2 || '%'`,
		h.tenant, subject).Scan(&count); err != nil {
		t.Fatalf("count certificates for %s: %v", subject, err)
	}
	return count
}
