package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/secrettext"
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
	token := secrettext.String(raw)
	secret.Wipe(raw)
	return token
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
	if status != http.StatusOK {
		t.Fatalf("get after idempotent double-rotate status = %d", status)
	}
	_ = json.Unmarshal(body, &rv)
	if rv.Version != 3 {
		t.Fatalf("after idempotent double-rotate, version = %d, want 3 (a single bump — AN-5)", rv.Version)
	}
}

// TestServedSecretStoreVersionHistoryAndPITR is the SEC-01 proof: the served secret
// store keeps prior sealed versions, can read an old version, can recover current
// state to a point in time, and keeps tenant B outside tenant A's version history.
func TestServedSecretStoreVersionHistoryAndPITR(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	tokA := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tokA,
		map[string]any{"name": "db/password", "value": "pitr-v1"})
	if status != http.StatusCreated {
		t.Fatalf("create secret: status %d body %s", status, body)
	}
	time.Sleep(10 * time.Millisecond)

	status, body = secretsReq(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", tokA,
		map[string]any{"value": "pitr-v2"})
	if status != http.StatusOK {
		t.Fatalf("rotate to v2: status %d body %s", status, body)
	}
	var meta struct {
		Version   int       `json:"version"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		t.Fatalf("decode v2 meta: %v (%s)", err, body)
	}
	if meta.Version != 2 {
		t.Fatalf("v2 rotate returned version %d, want 2", meta.Version)
	}
	recoverAt := meta.UpdatedAt.Add(time.Millisecond)
	time.Sleep(10 * time.Millisecond)

	status, body = secretsReq(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", tokA,
		map[string]any{"value": "pitr-v3"})
	if status != http.StatusOK {
		t.Fatalf("rotate to v3: status %d body %s", status, body)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/history/db/password?version=1", tokA, nil)
	if status != http.StatusOK {
		t.Fatalf("read prior version: status %d body %s", status, body)
	}
	var rv struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(body, &rv); err != nil {
		t.Fatalf("decode historical read: %v (%s)", err, body)
	}
	if rv.Value != "pitr-v1" || rv.Version != 1 {
		t.Fatalf("historical version read = value %q version %d, want pitr-v1/1", rv.Value, rv.Version)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store/recover/db/password", tokA,
		map[string]any{"at": recoverAt.Format(time.RFC3339Nano)})
	if status != http.StatusOK {
		t.Fatalf("recover to point in time: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "pitr-v2") {
		t.Fatalf("recover reply leaked the recovered secret value (AN-8): %s", body)
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		t.Fatalf("decode recover meta: %v (%s)", err, body)
	}
	if meta.Version != 4 {
		t.Fatalf("recover created version %d, want 4", meta.Version)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/db/password", tokA, nil)
	if status != http.StatusOK {
		t.Fatalf("read after recover: status %d body %s", status, body)
	}
	if err := json.Unmarshal(body, &rv); err != nil {
		t.Fatalf("decode recovered read: %v (%s)", err, body)
	}
	if rv.Value != "pitr-v2" || rv.Version != 4 {
		t.Fatalf("after recover = value %q version %d, want pitr-v2/4", rv.Value, rv.Version)
	}

	if !h.hasEvent(t, "secret.version.written") || !h.hasEvent(t, "secret.recovered") {
		t.Fatalf("served PITR did not emit secret.version.written and secret.recovered events")
	}
	if h.logContains(t, "pitr-v1") || h.logContains(t, "pitr-v2") || h.logContains(t, "pitr-v3") {
		t.Fatal("secret version history or recovery logged plaintext secret material")
	}

	const tenantB = "22222222-2222-2222-2222-222222222222"
	if _, err := h.store.CreateOwner(context.Background(), store.Owner{TenantID: tenantB, Kind: store.OwnerWorkload, Name: "tenant-b-pitr"}); err != nil {
		t.Fatalf("create tenant B owner: %v", err)
	}
	tokB := seedScopedToken(t, h.store, tenantB, "secrets:read", "secrets:write")
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/history/db/password?version=1", tokB, nil)
	if status != http.StatusNotFound {
		t.Fatalf("tenant B read tenant A history: status %d body %s", status, body)
	}
}

// TestServedSecretStoreReferencesAndImport is the SEC-02 proof: the served secret
// store resolves ${secret.path} references only when a caller explicitly requests
// resolution, imports a small tree of secrets, and rejects circular references with a
// structured problem response.
func TestServedSecretStoreReferencesAndImport(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	for _, seed := range []struct {
		name  string
		value string
	}{
		{name: "db/user", value: "payments"},
		{name: "db/password", value: "s3cr3t"},
		{name: "db/dsn", value: "postgres://${secret.db/user}:${secret.db/password}@db.internal/app"},
	} {
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
			map[string]any{"name": seed.name, "value": seed.value})
		if status != http.StatusCreated {
			t.Fatalf("create %s: status %d body %s", seed.name, status, body)
		}
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/db/dsn?resolve=true", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("resolve dsn: status %d body %s", status, body)
	}
	var rv struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(body, &rv); err != nil {
		t.Fatalf("decode resolved dsn: %v (%s)", err, body)
	}
	if rv.Value != "postgres://payments:s3cr3t@db.internal/app" {
		t.Fatalf("resolved dsn = %q, want references expanded", rv.Value)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store/import", tok,
		map[string]any{
			"prefix": "imported",
			"values": map[string]string{
				"api/token": "tok-1",
				"api/url":   "https://svc.internal?token=${secret.imported/api/token}",
			},
		})
	if status != http.StatusCreated {
		t.Fatalf("import tree: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "tok-1") {
		t.Fatalf("import reply leaked imported secret material: %s", body)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/imported/api/url?resolve=true", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("resolve imported tree: status %d body %s", status, body)
	}
	if err := json.Unmarshal(body, &rv); err != nil {
		t.Fatalf("decode resolved import: %v (%s)", err, body)
	}
	if rv.Value != "https://svc.internal?token=tok-1" {
		t.Fatalf("resolved import = %q, want imported reference expanded", rv.Value)
	}

	for _, seed := range []struct {
		name  string
		value string
	}{
		{name: "loop/a", value: "${secret.loop/b}"},
		{name: "loop/b", value: "${secret.loop/a}"},
	} {
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
			map[string]any{"name": seed.name, "value": seed.value})
		if status != http.StatusCreated {
			t.Fatalf("create %s: status %d body %s", seed.name, status, body)
		}
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/loop/a?resolve=true", tok, nil)
	if status != http.StatusConflict {
		t.Fatalf("circular reference status = %d body %s, want 409", status, body)
	}
	if !strings.Contains(string(body), "secret reference cycle") || !strings.Contains(string(body), `"cycle"`) {
		t.Fatalf("cycle response is not structured enough: %s", body)
	}
}

type servedDynamicSecretBackend struct {
	mu      sync.Mutex
	n       int
	live    map[string]bool
	revoked map[string]bool
}

func newServedDynamicSecretBackend() *servedDynamicSecretBackend {
	return &servedDynamicSecretBackend{live: map[string]bool{}, revoked: map[string]bool{}}
}

func (b *servedDynamicSecretBackend) Create(_ context.Context, role string) (string, []byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.n++
	ref := fmt.Sprintf("dyn-ref-%d", b.n)
	b.live[ref] = true
	return ref, []byte("dynamic-secret-" + ref + "-" + role), nil
}

func (b *servedDynamicSecretBackend) Revoke(_ context.Context, ref string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.live, ref)
	b.revoked[ref] = true
	return nil
}

func (b *servedDynamicSecretBackend) revokedCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.revoked)
}

func withDynamicSecretBackend(b dynsecret.Backend, interval time.Duration) func(*Deps) {
	return func(d *Deps) {
		d.DynamicSecretProviders = []dynsecret.Provider{dynsecret.NewProvider("stub", b)}
		d.DynamicLeaseWorkerInterval = interval
	}
}

// TestServedDynamicSecretLeasesIssueRenewRevokeAndExpire is the SEC-03 proof: the
// served API mounts internal/dynsecret.Engine for issue/renew/revoke, returns the
// generated credential only on issue, and the served leaseworker expires and revokes
// a short TTL lease through the durable revocation queue.
func TestServedDynamicSecretLeasesIssueRenewRevokeAndExpire(t *testing.T) {
	backend := newServedDynamicSecretBackend()
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		withDynamicSecretBackend(backend, 10*time.Millisecond),
	)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	worker, ok := any(h.srv).(interface{ RunDynamicLeaseWorker(context.Context) })
	if !ok {
		t.Fatal("served dynamic lease worker is not wired")
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

	type leaseValue struct {
		ID         string    `json:"id"`
		Provider   string    `json:"provider"`
		Role       string    `json:"role"`
		State      string    `json:"state"`
		Credential string    `json:"credential,omitempty"`
		IssuedAt   time.Time `json:"issued_at"`
		ExpiresAt  time.Time `json:"expires_at"`
	}

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases", tok,
		map[string]any{"provider": "stub", "role": "readonly", "ttl_seconds": 60})
	if status != http.StatusCreated {
		t.Fatalf("issue dynamic lease: status %d body %s", status, body)
	}
	var issued leaseValue
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("decode issued lease: %v (%s)", err, body)
	}
	if issued.ID == "" || issued.State != "active" || issued.Provider != "stub" || issued.Credential == "" {
		t.Fatalf("issued lease missing served fields: %+v", issued)
	}
	if h.logContains(t, issued.Credential) {
		t.Fatal("dynamic lease event log leaked generated credential material")
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+issued.ID+"/renew", tok,
		map[string]any{"extend_seconds": 60})
	if status != http.StatusOK {
		t.Fatalf("renew dynamic lease: status %d body %s", status, body)
	}
	var renewed leaseValue
	if err := json.Unmarshal(body, &renewed); err != nil {
		t.Fatalf("decode renewed lease: %v (%s)", err, body)
	}
	if !renewed.ExpiresAt.After(issued.ExpiresAt) || renewed.Credential != "" {
		t.Fatalf("renewed lease = %+v, want later expiry and no credential replay", renewed)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+issued.ID+"/revoke", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("revoke dynamic lease: status %d body %s", status, body)
	}
	var revoked leaseValue
	if err := json.Unmarshal(body, &revoked); err != nil {
		t.Fatalf("decode revoked lease: %v (%s)", err, body)
	}
	if revoked.State != "revoked" || revoked.Credential != "" {
		t.Fatalf("revoked lease = %+v, want revoked metadata only", revoked)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases", tok,
		map[string]any{"provider": "stub", "role": "short", "ttl_seconds": 1})
	if status != http.StatusCreated {
		t.Fatalf("issue expiring lease: status %d body %s", status, body)
	}
	var expiring leaseValue
	if err := json.Unmarshal(body, &expiring); err != nil {
		t.Fatalf("decode expiring lease: %v (%s)", err, body)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+expiring.ID, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read expiring lease: status %d body %s", status, body)
		}
		var current leaseValue
		if err := json.Unmarshal(body, &current); err != nil {
			t.Fatalf("decode expiring lease read: %v (%s)", err, body)
		}
		if current.State == "revoked" && backend.revokedCount() >= 2 {
			if !h.hasEvent(t, "dynsecret.lease.issued") || !h.hasEvent(t, "dynsecret.lease.renewed") || !h.hasEvent(t, "dynsecret.lease.revoked") {
				t.Fatalf("dynamic lease lifecycle did not emit issue/renew/revoke events")
			}
			return
		}
	}
	t.Fatalf("served leaseworker did not expire and revoke short lease; backend revoked %d", backend.revokedCount())
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

// TestServedSecretShareSurvivesRestart is the SEC-08 durable-share proof. A share
// is created through the served path, the API process is rebuilt against the same
// PostgreSQL/event-log/signer spine, and the restarted served handler redeems the
// token exactly once. The pre-fix tree keeps shares only in per-process memory, so
// the post-restart redeem returns 404.
func TestServedSecretShareSurvivesRestart(t *testing.T) {
	secretKEK, err := kek.LoadOrCreate(secretsTestKEKPath(t))
	if err != nil {
		t.Fatalf("secrets kek: %v", err)
	}
	t.Cleanup(secretKEK.Destroy)
	secretOpt := func(d *Deps) {
		d.EnableSecretsAPI = true
		d.KEK = secretKEK
	}

	h := newServedHarness(t, config.Protocols{}, secretOpt)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/shares", tok,
		map[string]any{"value": "restart-share-value", "ttl_seconds": 300})
	if status != http.StatusCreated {
		t.Fatalf("create share: status %d body %s", status, body)
	}
	var created struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode create share: %v (%s)", err, body)
	}
	if created.Token == "" {
		t.Fatal("created share returned empty token")
	}

	restarted, err := Build(context.Background(), Deps{
		Store:            h.store,
		Log:              h.log,
		Signer:           h.signer,
		SignAuthorizer:   h.authz,
		CACertFile:       h.caFile,
		KEK:              secretKEK,
		EnableSecretsAPI: true,
	})
	if err != nil {
		t.Fatalf("restart build: %v", err)
	}
	ts2 := httptest.NewServer(restarted.Handler())
	t.Cleanup(ts2.Close)
	restartedHarness := &servedHarness{ts: ts2}

	status, body = secretsReq(t, restartedHarness, http.MethodPost, "/api/v1/secrets/shares/redeem", tok,
		map[string]any{"token": created.Token})
	if status != http.StatusOK {
		t.Fatalf("redeem after restart: status %d body %s", status, body)
	}
	var redeemed struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &redeemed); err != nil {
		t.Fatalf("decode redeem: %v (%s)", err, body)
	}
	if redeemed.Value != "restart-share-value" {
		t.Fatalf("redeemed value = %q, want restart-share-value", redeemed.Value)
	}

	status, body = secretsReq(t, restartedHarness, http.MethodPost, "/api/v1/secrets/shares/redeem", tok,
		map[string]any{"token": created.Token})
	if status != http.StatusNotFound {
		t.Fatalf("second redeem after restart status = %d body %s, want 404", status, body)
	}
	if h.logContains(t, "restart-share-value") || h.logContains(t, created.Token) {
		t.Error("event log leaked durable share value or token (AN-8)")
	}
}

// TestServedSecretChangeRequiresDualControlApproval is the SEC-08 approval proof.
// With RequireApproval enabled, a sensitive secret-store mutation opens the existing
// dual-control request, rejects the requester before quorum, rejects self-approval,
// and succeeds only after m distinct approvers approve the secret action.
func TestServedSecretChangeRequiresDualControlApproval(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 2
	})
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "alice", "secrets:read", "secrets:write")
	approverA := seedScopedTokenSubject(t, h.store, h.tenant, "bob", "secrets:write")
	approverB := seedScopedTokenSubject(t, h.store, h.tenant, "carol", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", requester,
		map[string]any{"name": "db/password", "value": "dual-v1"})
	if status != http.StatusCreated {
		t.Fatalf("create secret: status %d body %s", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", requester, "sec08-rotate-denied",
		map[string]any{"value": "dual-v2"})
	if status != http.StatusForbidden {
		t.Fatalf("rotate before approvals status = %d body %s, want 403", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/db/password", requester, nil)
	if status != http.StatusOK {
		t.Fatalf("read after denied rotate: status %d body %s", status, body)
	}
	var rv struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(body, &rv); err != nil {
		t.Fatalf("decode secret: %v (%s)", err, body)
	}
	if rv.Value != "dual-v1" || rv.Version != 1 {
		t.Fatalf("denied rotate changed secret: value=%q version=%d", rv.Value, rv.Version)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/db/password", requester, "sec08-self-approval",
		map[string]any{"action": "rotate"})
	if status != http.StatusForbidden {
		t.Fatalf("self-approval status = %d body %s, want 403", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/db/password", approverA, "sec08-approval-bob",
		map[string]any{"action": "rotate"})
	if status != http.StatusOK {
		t.Fatalf("first distinct approval: status %d body %s", status, body)
	}
	var approval struct {
		Resource  string `json:"resource"`
		Action    string `json:"action"`
		Approver  string `json:"approver"`
		Approvals int    `json:"approvals"`
	}
	if err := json.Unmarshal(body, &approval); err != nil {
		t.Fatalf("decode first approval: %v (%s)", err, body)
	}
	if approval.Resource != "secret:db/password" || approval.Action != "rotate" || approval.Approver != "bob" || approval.Approvals != 1 {
		t.Fatalf("first approval response = %+v", approval)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/db/password", approverB, "sec08-approval-carol",
		map[string]any{"action": "rotate"})
	if status != http.StatusOK {
		t.Fatalf("second distinct approval: status %d body %s", status, body)
	}
	if err := json.Unmarshal(body, &approval); err != nil {
		t.Fatalf("decode second approval: %v (%s)", err, body)
	}
	if approval.Approver != "carol" || approval.Approvals != 2 {
		t.Fatalf("second approval response = %+v", approval)
	}

	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", requester, "sec08-rotate-approved",
		map[string]any{"value": "dual-v2"})
	if status != http.StatusOK {
		t.Fatalf("rotate after approvals: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/db/password", requester, nil)
	if status != http.StatusOK {
		t.Fatalf("read after approved rotate: status %d body %s", status, body)
	}
	if err := json.Unmarshal(body, &rv); err != nil {
		t.Fatalf("decode rotated secret: %v (%s)", err, body)
	}
	if rv.Value != "dual-v2" || rv.Version != 2 {
		t.Fatalf("approved rotate result: value=%q version=%d, want dual-v2/2", rv.Value, rv.Version)
	}

	status, body = secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/db/password", requester, "sec08-delete-denied", nil)
	if status != http.StatusForbidden {
		t.Fatalf("delete before approvals status = %d body %s, want 403", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/db/password", approverA, "sec08-delete-approval-bob",
		map[string]any{"action": "delete"})
	if status != http.StatusOK {
		t.Fatalf("first delete approval: status %d body %s", status, body)
	}
	if err := json.Unmarshal(body, &approval); err != nil {
		t.Fatalf("decode first delete approval: %v (%s)", err, body)
	}
	if approval.Resource != "secret:db/password" || approval.Action != "delete" || approval.Approver != "bob" || approval.Approvals != 1 {
		t.Fatalf("first delete approval response = %+v", approval)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/db/password", approverB, "sec08-delete-approval-carol",
		map[string]any{"action": "delete"})
	if status != http.StatusOK {
		t.Fatalf("second delete approval: status %d body %s", status, body)
	}
	if err := json.Unmarshal(body, &approval); err != nil {
		t.Fatalf("decode second delete approval: %v (%s)", err, body)
	}
	if approval.Action != "delete" || approval.Approver != "carol" || approval.Approvals != 2 {
		t.Fatalf("second delete approval response = %+v", approval)
	}
	status, body = secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/db/password", requester, "sec08-delete-approved", nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete after approvals: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/db/password", requester, nil)
	if status != http.StatusNotFound {
		t.Fatalf("read after approved delete: status %d body %s, want 404", status, body)
	}
	if h.logContains(t, "dual-v1") || h.logContains(t, "dual-v2") {
		t.Error("event log leaked a dual-control secret value (AN-8)")
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

	// Mint a workload token the served TokenMethod will accept (same HMAC secret,
	// tenant MAC-bound so X-Tenant-ID is only a lookup hint).
	method := authmethod.TokenMethod{Secret: authSecret, TenantID: h.tenant, Scopes: map[string][]string{"workload-1": {"secrets:read"}}}
	cred, err := method.Issue("workload-1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue workload token: %v", err)
	}

	// LOGIN (public route; the tenant header must match the credential-bound tenant).
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

func TestServedMachineLoginRejectsCrossTenantHeader(t *testing.T) {
	authSecret := []byte("super-secret-hmac-key-for-machine-login")
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, authSecret))
	tenantB := "22222222-2222-2222-2222-222222222222"

	method := authmethod.TokenMethod{Secret: authSecret, TenantID: h.tenant, Scopes: map[string][]string{"workload-1": {"secrets:read"}}}
	cred, err := method.Issue("workload-1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue tenant-A workload token: %v", err)
	}

	bodyBytes, _ := json.Marshal(map[string]any{"method": "token", "credential": cred})
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantB)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("cross-tenant login request: %v", err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tenant-A token with tenant-B header: status %d body %s, want 401", resp.StatusCode, data)
	}
	if strings.Contains(string(data), cred) {
		t.Error("cross-tenant rejection echoed the credential (AN-8 violation)")
	}
}

// TestServedMachineLoginTopMethodsKubernetesSATAndAWSIAM is the IAM-01 acceptance:
// the same PUBLIC /api/v1/secrets/login route accepts top-market machine auth
// methods beyond the HMAC token method. A Kubernetes pod presents a projected
// ServiceAccount JWT signed by the cluster issuer; an AWS workload presents a
// signed STS GetCallerIdentity request that the method verifies through an
// emulated STS boundary. Both are tenant-scoped: replaying tenant A's credential
// with tenant B's header fails closed.
func TestServedMachineLoginTopMethodsKubernetesSATAndAWSIAM(t *testing.T) {
	const tenantB = "22222222-2222-2222-2222-222222222222"
	now := time.Date(2026, 6, 25, 18, 0, 0, 0, time.UTC)

	k8sSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate k8s SAT signer: %v", err)
	}
	t.Cleanup(k8sSigner.Destroy)
	k8sJWK, err := crypto.PublicJWK(k8sSigner.Public(), "k8s-k1")
	if err != nil {
		t.Fatalf("k8s jwk: %v", err)
	}
	k8sJWKS := crypto.JWKS{Keys: []crypto.JWK{k8sJWK}}
	k8sClaims := map[string]any{
		"iss":               "https://kubernetes.default.svc",
		"aud":               []string{"trstctl"},
		"sub":               "system:serviceaccount:payments:api",
		"exp":               now.Add(time.Hour).Unix(),
		"iat":               now.Add(-time.Minute).Unix(),
		"trstctl.io/tenant": servedTestTenant,
		"scopes":            []string{"secrets:read"},
		"kubernetes.io": map[string]any{
			"namespace": "payments",
			"serviceaccount": map[string]any{
				"name": "api",
				"uid":  "sa-uid-1",
			},
			"pod": map[string]any{
				"name": "api-7d9",
				"uid":  "pod-uid-1",
			},
		},
	}
	k8sToken, err := crypto.SignJWT(k8sSigner, "k8s-k1", k8sClaims)
	if err != nil {
		t.Fatalf("sign k8s SAT: %v", err)
	}

	fakeSTS := &servedFakeSTS{
		identity: authmethod.AWSIdentity{
			Account: "123456789012",
			ARN:     "arn:aws:sts::123456789012:assumed-role/trstctl-web/i-abc123",
			UserID:  "AROATEST:web",
		},
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.MachineAuthMethods = func(tenantID string) []authmethod.Method {
			allowedAWSAccounts := map[string]bool{"210987654321": true}
			if tenantID == servedTestTenant {
				allowedAWSAccounts = map[string]bool{"123456789012": true}
			}
			return []authmethod.Method{
				authmethod.KubernetesSATMethod{
					JWKS:              k8sJWKS,
					Issuer:            "https://kubernetes.default.svc",
					Audience:          "trstctl",
					TenantID:          tenantID,
					TenantClaim:       "trstctl.io/tenant",
					AllowedNamespaces: map[string]bool{"payments": true},
					AllowedServiceAccounts: map[string]bool{
						"payments/api": true,
					},
					Now: func() time.Time { return now },
				},
				authmethod.AWSIAMMethod{
					TenantID:        tenantID,
					Client:          fakeSTS,
					AllowedAccounts: allowedAWSAccounts,
					Scopes:          []string{"secrets:read"},
				},
			}
		}
	})

	status, body := servedMachineLogin(t, h, servedTestTenant, "kubernetes", k8sToken)
	if status != http.StatusOK {
		t.Fatalf("kubernetes SAT login: status %d body %s", status, body)
	}
	var k8sSession struct {
		Principal string   `json:"principal"`
		Method    string   `json:"method"`
		Scopes    []string `json:"scopes"`
	}
	if err := json.Unmarshal(body, &k8sSession); err != nil {
		t.Fatalf("decode k8s login: %v (%s)", err, body)
	}
	if k8sSession.Method != "kubernetes" || k8sSession.Principal != "system:serviceaccount:payments:api" || len(k8sSession.Scopes) != 1 || k8sSession.Scopes[0] != "secrets:read" {
		t.Fatalf("kubernetes session = %+v", k8sSession)
	}
	status, body = servedMachineLogin(t, h, tenantB, "kubernetes", k8sToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("cross-tenant k8s SAT login: status %d body %s, want 401", status, body)
	}
	if strings.Contains(string(body), k8sToken) {
		t.Fatal("cross-tenant k8s rejection echoed the credential")
	}

	awsCredential := `{"method":"POST","url":"https://sts.amazonaws.com/","body":"Action=GetCallerIdentity&Version=2011-06-15"}`
	status, body = servedMachineLogin(t, h, servedTestTenant, "aws-iam", awsCredential)
	if status != http.StatusOK {
		t.Fatalf("aws iam login: status %d body %s", status, body)
	}
	var awsSession struct {
		Principal string   `json:"principal"`
		Method    string   `json:"method"`
		Scopes    []string `json:"scopes"`
	}
	if err := json.Unmarshal(body, &awsSession); err != nil {
		t.Fatalf("decode aws login: %v (%s)", err, body)
	}
	if awsSession.Method != "aws-iam" || awsSession.Principal != fakeSTS.identity.ARN || len(awsSession.Scopes) != 1 || awsSession.Scopes[0] != "secrets:read" {
		t.Fatalf("aws session = %+v", awsSession)
	}
	if fakeSTS.calls == 0 {
		t.Fatal("aws-iam login did not call the STS GetCallerIdentity verifier")
	}
	status, body = servedMachineLogin(t, h, tenantB, "aws-iam", awsCredential)
	if status != http.StatusUnauthorized {
		t.Fatalf("cross-tenant aws iam login: status %d body %s, want 401", status, body)
	}
	if strings.Contains(string(body), awsCredential) {
		t.Fatal("cross-tenant aws rejection echoed the credential")
	}
}

type servedFakeSTS struct {
	identity authmethod.AWSIdentity
	calls    int
}

func (s *servedFakeSTS) GetCallerIdentity(_ context.Context, credential []byte) (authmethod.AWSIdentity, error) {
	if len(credential) == 0 {
		return authmethod.AWSIdentity{}, fmt.Errorf("empty signed STS credential")
	}
	s.calls++
	return s.identity, nil
}

func servedMachineLogin(t *testing.T, h *servedHarness, tenantID, method, credential string) (int, []byte) {
	t.Helper()
	bodyBytes, err := json.Marshal(map[string]any{"method": method, "credential": credential})
	if err != nil {
		t.Fatalf("marshal machine login: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/login", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("new machine login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("machine login request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
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
