package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// This file is the GAP-006 / EXC-WIRE-secrets wire-in PROOF: it drives the SERVED
// secrets/identity surface on the assembled control plane (server.Build -> Handler,
// the SAME composition cmd/trstctl serves) over its real HTTP API, exercising all
// four mounted frameworks end-to-end:
//
//   - the secret store (secretsdk/F64): create -> read -> rotate, sealed at rest;
//   - one-time secret sharing (secretshare/F60): create a share, redeem it ONCE; a
//     second redeem fails (single-use);
//   - the dynamic PKI secret (pkisecret/F67): issue a cert + key and verify the pair
//     is a usable TLS identity (tls.X509KeyPair) signed by the served CA;
//   - machine login (authmethod/F58): a workload token credential yields a session;
//   - cross-tenant isolation (AN-1): tenant B cannot read tenant A's secret.
//
// On the PRE-wiring tree these routes do not exist (the five frameworks have zero
// importers on the served path), so the requests 404 and the test fails; post-wiring
// they are served and it passes.

// secretsTestKEKPath returns a per-test KEK file path under t.TempDir.
func secretsTestKEKPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "secrets-kek.bin")
}

// withSecretsEnabled is a harness option that turns on the served secrets surface
// with a fresh retained KEK and a machine-login HMAC secret — mirroring what Run
// wires from config.Secrets when secrets.enable_api is on.
func withSecretsEnabled(t *testing.T, authSecret []byte) func(*Deps) {
	t.Helper()
	kekW, err := kek.LoadOrCreate(secretsTestKEKPath(t))
	if err != nil {
		t.Fatalf("secrets kek: %v", err)
	}
	t.Cleanup(kekW.Destroy)
	return func(d *Deps) {
		d.EnableSecretsAPI = true
		d.KEK = kekW
		d.SecretsAuthSecret = authSecret
	}
}

// seedScopedToken creates a tenant-scoped API token carrying the given RBAC scopes
// and returns its raw bearer value, so the served secrets routes are driven through
// the SAME authenticated path the binary serves (bearer token -> principal -> RBAC).
func seedScopedToken(t *testing.T, st *store.Store, tenant string, scopes ...string) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if _, err := st.CreateAPIToken(context.Background(), store.APITokenRecord{
		TenantID: tenant, TokenHash: hash, Subject: "secrets-test", Scopes: scopes,
	}); err != nil {
		t.Fatalf("seed api token: %v", err)
	}
	return raw
}

// secretsReq issues an authenticated JSON request against the served handler and
// returns the status and body. token authenticates (bearer); tenant is sent in
// X-Tenant-ID (ignored by the served path once the bearer principal is resolved, but
// harmless), and a fresh Idempotency-Key is sent for mutations.
func secretsReq(t *testing.T, h *servedHarness, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		// A per-(method,path) idempotency key; callers that need a STABLE key across two
		// calls (the AN-5 retry probe) set it explicitly via secretsReqKey.
		req.Header.Set("Idempotency-Key", method+":"+path+":"+strconv.FormatInt(time.Now().UnixNano(), 10))
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// secretsReqKey is secretsReq with an explicit (stable) Idempotency-Key, for the
// retry/replay probe.
func secretsReqKey(t *testing.T, h *servedHarness, method, path, token, idemKey string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Idempotency-Key", idemKey)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// TestServedSecretStoreCreateReadRotate is the secret-store (secretsdk/F64) proof:
// create -> read (value matches) -> rotate (version bumps, new value reads back). It
// drives the SERVED /api/v1/secrets/store/* routes on the assembled binary. The
// value is sealed at rest (only the read endpoint returns it). It fails on the
// pre-wiring tree (the routes 404).
func TestServedSecretStoreCreateReadRotate(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	if !h.srv.handlerServesSecrets() {
		t.Fatal("served handler does not mount the secrets surface — GAP-006 wiring missing")
	}
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	// CREATE.
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
		map[string]any{"name": "db/password", "value": "s3cr3t-v1"})
	if status != http.StatusCreated {
		t.Fatalf("create secret: status %d body %s", status, body)
	}
	// The create reply is metadata only — it must NOT carry the value (AN-8).
	if strings.Contains(string(body), "s3cr3t-v1") {
		t.Fatalf("create reply leaked the secret value (AN-8): %s", body)
	}

	// READ — the value comes back exactly here, to the authorized caller.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/db/password", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("read secret: status %d body %s", status, body)
	}
	var rv struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(body, &rv); err != nil {
		t.Fatalf("decode read: %v (%s)", err, body)
	}
	if rv.Value != "s3cr3t-v1" {
		t.Fatalf("read value = %q, want the created value", rv.Value)
	}
	if rv.Version != 1 {
		t.Fatalf("read version = %d, want 1", rv.Version)
	}

	// ROTATE — new value, bumped version.
	status, body = secretsReq(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", tok,
		map[string]any{"value": "s3cr3t-v2"})
	if status != http.StatusOK {
		t.Fatalf("rotate secret: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "s3cr3t-v2") {
		t.Fatalf("rotate reply leaked the new value (AN-8): %s", body)
	}

	// READ AGAIN — rotated value, version 2.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/db/password", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("read after rotate: status %d body %s", status, body)
	}
	_ = json.Unmarshal(body, &rv)
	if rv.Value != "s3cr3t-v2" || rv.Version != 2 {
		t.Fatalf("after rotate: value=%q version=%d, want s3cr3t-v2/2", rv.Value, rv.Version)
	}

	// Event-sourced (AN-2): the create + rotate emitted events.
	if !h.hasEvent(t, "secret.created") {
		t.Error("no secret.created event — the served secret create was not event-sourced (AN-2)")
	}
	if !h.hasEvent(t, "secret.rotated") {
		t.Error("no secret.rotated event — the served secret rotate was not event-sourced (AN-2)")
	}
	// The event log must NOT contain the secret value anywhere (AN-8).
	if h.logContains(t, "s3cr3t-v1") || h.logContains(t, "s3cr3t-v2") {
		t.Error("the event log contains a secret value (AN-8 violation)")
	}

	// AN-5: a rotate replayed with the SAME Idempotency-Key returns the original result
	// and does NOT bump the version a second time.
	idem := "rotate-once"
	s1, _ := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", tok, idem,
		map[string]any{"value": "s3cr3t-v3"})
	s2, _ := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", tok, idem,
		map[string]any{"value": "s3cr3t-v3"})
	if s1 != http.StatusOK || s2 != http.StatusOK {
		t.Fatalf("idempotent rotate statuses = %d, %d", s1, s2)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/db/password", tok, nil)
	_ = json.Unmarshal(body, &rv)
	if rv.Version != 3 {
		t.Fatalf("after idempotent double-rotate, version = %d, want 3 (a single bump — AN-5)", rv.Version)
	}
}

// TestServedSecretShareRedeemOnce is the one-time-share (secretshare/F60, GAP-001)
// proof: create a share, redeem it ONCE (value returned), then a SECOND redeem of the
// same token fails (single-use). It also asserts the share token is never written to
// the event log (the GAP-001 fix). It fails on the pre-wiring tree.
func TestServedSecretShareRedeemOnce(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	// CREATE share.
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/shares", tok,
		map[string]any{"value": "one-time-secret", "ttl_seconds": 3600})
	if status != http.StatusCreated {
		t.Fatalf("create share: status %d body %s", status, body)
	}
	var cr struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &cr); err != nil || cr.Token == "" {
		t.Fatalf("decode share token: %v (%s)", err, body)
	}

	// REDEEM once — the value comes back.
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/shares/redeem", tok,
		map[string]any{"token": cr.Token})
	if status != http.StatusOK {
		t.Fatalf("first redeem: status %d body %s", status, body)
	}
	var rd struct {
		Value string `json:"value"`
	}
	_ = json.Unmarshal(body, &rd)
	if rd.Value != "one-time-secret" {
		t.Fatalf("redeemed value = %q, want the shared value", rd.Value)
	}

	// REDEEM again — single-use: the second redeem MUST fail.
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/shares/redeem", tok,
		map[string]any{"token": cr.Token})
	if status == http.StatusOK {
		t.Fatalf("second redeem succeeded — the one-time share was redeemable twice (single-use broken): %s", body)
	}

	// GAP-001: the token must never appear in the audit/event log.
	if h.logContains(t, cr.Token) {
		t.Error("the share token appears in the event log (GAP-001 regression — token must never be logged)")
	}
	// The shared value must never appear in the event log either (AN-8).
	if h.logContains(t, "one-time-secret") {
		t.Error("the shared secret value appears in the event log (AN-8 violation)")
	}
}

// TestServedPKISecretIssuesUsableKeypair is the dynamic-PKI-secret (pkisecret/F67,
// GAP-004) proof: issue a dynamic secret and assert the returned cert + key form a
// USABLE TLS identity (tls.X509KeyPair succeeds) signed by the served CA. A bare cert
// with no key (the GAP-004 defect) would fail X509KeyPair. It fails on the pre-wiring
// tree.
func TestServedPKISecretIssuesUsableKeypair(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/pki", tok,
		map[string]any{"common_name": "svc.internal", "ttl_seconds": 3600})
	if status != http.StatusCreated {
		t.Fatalf("issue pki secret: status %d body %s", status, body)
	}
	var ps struct {
		Serial      string `json:"serial"`
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(body, &ps); err != nil {
		t.Fatalf("decode pki secret: %v (%s)", err, body)
	}
	if ps.Certificate == "" || ps.PrivateKey == "" {
		t.Fatalf("pki secret is missing the cert or key (GAP-004): cert=%d key=%d bytes", len(ps.Certificate), len(ps.PrivateKey))
	}
	// GAP-004 acceptance: the cert + key load as a TLS key pair (a bare cert would
	// fail). The check routes through the crypto boundary (AN-3) rather than importing
	// crypto/tls here — it is exactly tls.X509KeyPair under the hood.
	if err := crypto.VerifyCertKeyMatchPEM([]byte(ps.Certificate), []byte(ps.PrivateKey)); err != nil {
		t.Fatalf("the dynamic PKI secret cert/key are not a usable TLS identity (GAP-004): %v", err)
	}
	// The leaf verifies against the served issuing CA (AN-3/AN-4 — signed in the signer).
	leaf := pemCertDER(t, []byte(ps.Certificate))
	if err := crypto.VerifyLeafSignedByCA(leaf, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("dynamic PKI secret leaf does not verify against the served CA: %v", err)
	}
	// Event-sourced (AN-2): issuance was recorded; the private key is never in the log.
	if !h.hasEvent(t, "pkisecret.issued") {
		t.Error("no pkisecret.issued event — the served dynamic PKI secret was not event-sourced (AN-2)")
	}
	if h.logContains(t, ps.PrivateKey) || h.logContains(t, "PRIVATE KEY") {
		t.Error("the event log contains the dynamic-secret private key (AN-8 violation)")
	}
}

// TestServedMachineLogin is the machine-login (authmethod/F58) proof: a workload
// presents a token credential to the PUBLIC /api/v1/secrets/login route and
// receives a scoped, tenant-scoped session. It fails on the pre-wiring tree.
func TestServedMachineLogin(t *testing.T) {
	authSecret := []byte("super-secret-hmac-key-for-machine-login")
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, authSecret))

	// Mint a workload token the served TokenMethod will accept (same HMAC secret).
	method := authmethod.TokenMethod{Secret: authSecret, Scopes: map[string][]string{"workload-1": {"secrets:read"}}}
	cred, err := method.Issue("workload-1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue workload token: %v", err)
	}

	// LOGIN (public route; tenant via header since the login establishes the principal).
	bodyBytes, _ := json.Marshal(map[string]any{"method": "token", "credential": cred})
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", h.tenant)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("machine login: status %d body %s", resp.StatusCode, data)
	}
	var sess struct {
		SessionID string   `json:"session_id"`
		Principal string   `json:"principal"`
		Scopes    []string `json:"scopes"`
	}
	if err := json.Unmarshal(data, &sess); err != nil {
		t.Fatalf("decode session: %v (%s)", err, data)
	}
	if sess.SessionID == "" || sess.Principal != "workload-1" {
		t.Fatalf("login session = %+v, want a session for workload-1", sess)
	}
	// The credential must never be echoed back.
	if strings.Contains(string(data), cred) {
		t.Error("the login response echoes the credential (AN-8 violation)")
	}

	// A bad credential is rejected (fail closed).
	badBody, _ := json.Marshal(map[string]any{"method": "token", "credential": "workload-1.0.deadbeef"})
	req2, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/login", bytes.NewReader(badBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Tenant-ID", h.tenant)
	resp2, _ := h.ts.Client().Do(req2)
	_ = resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Error("machine login accepted a forged token (fail-closed broken)")
	}
}

// TestServedSecretsCrossTenantDenial is the AN-1 isolation proof: tenant A creates a
// secret; a tenant B token (a DISTINCT tenant) cannot read it — the served read is
// RLS-isolated, so B gets 404, never A's value. It fails on the pre-wiring tree.
func TestServedSecretsCrossTenantDenial(t *testing.T) {
	const tenantB = "22222222-2222-2222-2222-222222222222"
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	// Make tenant B a real, distinct tenant by giving it a row of its own (the
	// established way the other two-tenant tests bring a second tenant into being).
	if _, err := h.store.CreateOwner(context.Background(), store.Owner{TenantID: tenantB, Kind: store.OwnerWorkload, Name: "tenant-b"}); err != nil {
		t.Fatalf("create tenant B owner: %v", err)
	}

	tokA := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	tokB := seedScopedToken(t, h.store, tenantB, "secrets:read", "secrets:write")

	// Tenant A creates a secret.
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tokA,
		map[string]any{"name": "tenant-a-only", "value": "A-private-value"})
	if status != http.StatusCreated {
		t.Fatalf("tenant A create: status %d body %s", status, body)
	}

	// Tenant A can read it back.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/tenant-a-only", tokA, nil)
	if status != http.StatusOK || !strings.Contains(string(body), "A-private-value") {
		t.Fatalf("tenant A read of its own secret failed: status %d body %s", status, body)
	}

	// Tenant B MUST NOT see it: a different tenant's read is RLS-isolated -> 404, and
	// the value never leaks (AN-1).
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/tenant-a-only", tokB, nil)
	if status == http.StatusOK {
		t.Fatalf("CROSS-TENANT LEAK (AN-1): tenant B read tenant A's secret: %s", body)
	}
	if strings.Contains(string(body), "A-private-value") {
		t.Fatalf("CROSS-TENANT LEAK (AN-1): tenant B's response contains tenant A's value: %s", body)
	}

	// Tenant B listing its own secrets must not include tenant A's name either.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store", tokB, nil)
	if status != http.StatusOK {
		t.Fatalf("tenant B list: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "tenant-a-only") {
		t.Fatalf("CROSS-TENANT LEAK (AN-1): tenant B's list includes tenant A's secret name: %s", body)
	}
}

// logContains reports whether any event payload for the harness OR any tenant in the
// log contains the substring — used to assert a secret/token NEVER reaches the log
// (AN-8 / GAP-001). It scans ALL tenants so a value is never accepted anywhere.
func (h *servedHarness) logContains(t *testing.T, substr string) bool {
	t.Helper()
	found := false
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if bytes.Contains(e.Data, []byte(substr)) {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	return found
}

// handlerServesSecrets reports whether the assembled server's API mounts the secrets
// surface — the GAP-006 wiring assertion at the server level (it delegates to the
// API's SecretsServed). It is defined on *Server so the test can assert the served
// composition, not a library function.
func (s *Server) handlerServesSecrets() bool { return s.apiSecretsServed() }

// pemCertDER decodes the first CERTIFICATE block of a PEM bundle to DER (a tiny test
// helper local to the secrets proof so it does not depend on the protocols test).
func pemCertDER(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	rest := pemBytes
	for {
		blk, tail := pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			return blk.Bytes
		}
		rest = tail
	}
	t.Fatalf("no CERTIFICATE block in PEM: %s", string(pemBytes))
	return nil
}
