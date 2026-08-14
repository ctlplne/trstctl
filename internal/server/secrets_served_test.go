// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kek"
	cryptoseal "trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
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

func TestBuildSecretsBackendDoesNotWireLegacySecretSyncQueueAUD109(t *testing.T) {
	srv := &Server{outbox: &orchestrator.Outbox{}}
	backend := srv.buildSecretsBackend(Deps{})
	if backend.QueueSecretSync == nil {
		t.Fatal("production backend omitted event-backed secret-sync queue")
	}
}

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

// withProtectedSecretsEnabled mirrors the production composition closely enough
// for served retry tests to prove they traverse the tenant-bound protected-result
// reader instead of a plaintext compatibility path.
func withProtectedSecretsEnabled(t *testing.T, authSecret []byte) func(*Deps) {
	t.Helper()
	withSecrets := withSecretsEnabled(t, authSecret)
	return func(d *Deps) {
		withSecrets(d)
		registry, err := tenantseal.NewLocalWrapperRegistry(nil)
		if err != nil {
			t.Fatalf("tenant wrapper registry: %v", err)
		}
		access, err := tenantseal.NewAccess(d.Store, d.KEK, registry)
		if err != nil {
			t.Fatalf("tenant crypto access: %v", err)
		}
		protector, err := tenantseal.NewResultProtector(access)
		if err != nil {
			t.Fatalf("idempotency result protector: %v", err)
		}
		d.TenantCrypto = access
		d.IdempotencyResultProtector = protector
	}
}

type selectivelyBlockedTenantAccess struct {
	mu      sync.RWMutex
	wrapper cryptoseal.KeyWrapper
	blocked map[string]bool
}

func (a *selectivelyBlockedTenantAccess) WithTenant(
	_ context.Context,
	tenantID string,
	fn func(tenantseal.Cipher) error,
) error {
	a.mu.RLock()
	blocked := a.blocked[tenantID]
	a.mu.RUnlock()
	if blocked {
		return tenantseal.CustodyUnavailable(errors.New("fixture tenant custody offline"))
	}
	return fn(legacyTenantTestCipher{wrapper: a.wrapper})
}

func (a *selectivelyBlockedTenantAccess) setBlocked(tenantID string, blocked bool) {
	a.mu.Lock()
	a.blocked[tenantID] = blocked
	a.mu.Unlock()
}

type legacyTenantTestCipher struct{ wrapper cryptoseal.KeyWrapper }

func (c legacyTenantTestCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	return cryptoseal.Seal(c.wrapper, plaintext, aad)
}

func (c legacyTenantTestCipher) Open(container, aad []byte) ([]byte, error) {
	return cryptoseal.Open(c.wrapper, container, aad)
}

type failingTenantCipherAccess struct{}

func (failingTenantCipherAccess) WithTenant(
	_ context.Context,
	_ string,
	fn func(tenantseal.Cipher) error,
) error {
	return fn(failingTenantCipher{})
}

type failingTenantCipher struct{}

func (failingTenantCipher) Seal([]byte, []byte) ([]byte, error) {
	return nil, errors.New("fixture sealer unavailable")
}

func (failingTenantCipher) Open([]byte, []byte) ([]byte, error) {
	return nil, errors.New("fixture sealer unavailable")
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

// registerServedTenant appends and projects the tenant lifecycle root used by
// epoch-bound application- and dynamic-secret commands. The served harness resets
// PostgreSQL for every test, so API-token fixtures alone do not establish a live
// tenant epoch.
func registerServedTenant(t *testing.T, h *servedHarness, name string) {
	t.Helper()
	registerServedTenantID(t, h, h.tenant, name)
}

func registerServedTenantID(t *testing.T, h *servedHarness, tenantID, name string) {
	t.Helper()
	data, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		t.Fatalf("marshal tenant registration: %v", err)
	}
	event, err := h.log.Append(context.Background(), events.Event{
		Type:     projections.EventTenantRegistered,
		TenantID: tenantID,
		Data:     data,
	})
	if err != nil {
		t.Fatalf("append tenant registration: %v", err)
	}
	if err := projections.New(h.store).Apply(context.Background(), event); err != nil {
		t.Fatalf("project tenant registration: %v", err)
	}
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
	registerServedTenant(t, h, "served secret create/read/rotate tenant")
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
	registerServedTenant(t, h, "served secret version history tenant")
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
	registerServedTenant(t, h, "served secret store reference tenant")
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
	if rv.Value != "postgres://payments:s3cr3t@db.internal/app" { // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
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
	if status != http.StatusNotImplemented {
		t.Fatalf("unsafe direct-write import status=%d body=%s, want fail-closed 501", status, body)
	}
	if strings.Contains(string(body), "tok-1") {
		t.Fatalf("import reply leaked imported secret material: %s", body)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/imported/api/url?resolve=true", tok, nil)
	if status != http.StatusNotFound {
		t.Fatalf("fail-closed import wrote secret rows: status=%d body=%s", status, body)
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
		d.DynamicSecretProviders = []dynsecret.Provider{servedRenewableDynamicSecretProvider{
			Provider: dynsecret.NewProvider("stub", b),
		}}
		d.DynamicLeaseWorkerInterval = interval
	}
}

type servedRenewableDynamicSecretProvider struct{ dynsecret.Provider }

func (servedRenewableDynamicSecretProvider) MaximumTTL() time.Duration { return time.Hour }

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
	registerServedTenant(t, h, "served dynamic-secret tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	worker, ok := any(h.srv).(interface{ RunDynamicLeaseWorker(context.Context) })
	if !ok {
		t.Fatal("served dynamic lease worker is not wired")
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	dispatcherDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		worker.RunDynamicLeaseWorker(workerCtx)
	}()
	go func() {
		defer close(dispatcherDone)
		h.srv.RunDispatcher(workerCtx)
	}()
	t.Cleanup(func() {
		cancelWorker()
		<-workerDone
		<-dispatcherDone
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
			if !h.hasEvent(t, projections.EventDynamicSecretLeaseIssued) ||
				!h.hasEvent(t, projections.EventDynamicSecretLeaseRenewed) ||
				!h.hasEvent(t, projections.EventDynamicSecretLeaseRevocationRequested) ||
				!h.hasEvent(t, projections.EventDynamicSecretLeaseRevocationCompleted) {
				t.Fatalf("dynamic lease lifecycle did not emit issue/renew/revocation events")
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

// TestServedSecretChangeRequiresDualControlApproval proves that a secret approval
// is an exact, one-shot capability. The immutable request binds the requester,
// current/result versions, raw idempotency-key digest, surface, and command HMAC;
// the projector spends it in the same transaction as the sealed mutation.
func TestServedSecretChangeRequiresDualControlApproval(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 2
	})
	registerServedTenant(t, h, "served dual-control application-secret tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "alice", "secrets:read", "secrets:write")
	approverA := seedScopedTokenSubject(t, h.store, h.tenant, "bob", "secrets:write")
	approverB := seedScopedTokenSubject(t, h.store, h.tenant, "carol", "secrets:write")
	ctx := context.Background()

	pendingApproval := func(action string, targetVersion uint64, excludeID string) store.OperationApprovalRequest {
		t.Helper()
		rows, err := h.store.ListOperationApprovals(ctx, h.tenant, "", 100)
		if err != nil {
			t.Fatalf("list exact approval requests: %v", err)
		}
		for _, row := range rows {
			if row.ID != excludeID && row.ResourceKind == "secret" && row.ResourceID == "secret:db/password" &&
				row.Action == action && row.TargetVersion == targetVersion {
				return row
			}
		}
		t.Fatalf("missing exact approval for %s at version %d: %+v", action, targetVersion, rows)
		return store.OperationApprovalRequest{}
	}
	approve := func(token, subject, key string, approval store.OperationApprovalRequest) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/db/password", token, key,
			map[string]any{"action": approval.Action, "request_id": approval.ID, "intent_digest": approval.IntentDigest})
		if status != http.StatusOK {
			t.Fatalf("%s exact approval: status %d body %s", subject, status, body)
		}
	}
	fencedActor := func() *events.Actor {
		t.Helper()
		fence, err := h.store.GetApplicationSecretMutationFence(ctx, h.tenant, "db/password")
		if err != nil || fence.Actor == nil || fence.Actor.Subject != "alice" {
			t.Fatalf("application-secret approval fence actor=%+v err=%v", fence.Actor, err)
		}
		return &events.Actor{Subject: fence.Actor.Subject, Roles: append([]string(nil), fence.Actor.Roles...)}
	}
	assertTargetActor := func(approval store.OperationApprovalRequest, want *events.Actor) {
		t.Helper()
		spent, err := h.store.GetOperationApproval(ctx, h.tenant, approval.ID)
		if err != nil || spent.Status != store.ApprovalStatusConsumed || spent.ConsumedEventID == "" {
			t.Fatalf("load consumed actor authority: %+v err=%v", spent, err)
		}
		target, found, err := h.log.EventByID(ctx, spent.ConsumedEventID)
		if err != nil || !found || !reflect.DeepEqual(target.Actor, want) {
			t.Fatalf("target actor=%+v, want exact fence actor %+v; found=%t err=%v",
				target.Actor, want, found, err)
		}
	}

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", requester,
		map[string]any{"name": "db/password", "value": "dual-v1"})
	if status != http.StatusCreated {
		t.Fatalf("create secret: status %d body %s", status, body)
	}

	const rotateKey = "sec08-rotate-exact"
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", requester, rotateKey,
		map[string]any{"value": "dual-v2"})
	if status != http.StatusForbidden {
		t.Fatalf("rotate before approvals status = %d body %s, want 403", status, body)
	}
	rotateActor := fencedActor()
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
	rotateApproval := pendingApproval("rotate", 1, "")
	if rotateApproval.Requester != "alice" || rotateApproval.FromState != "version:1" ||
		!strings.HasPrefix(rotateApproval.ToState, "version:2:command-hmac-sha256:") {
		t.Fatalf("rotate approval is not exact: %+v", rotateApproval)
	}
	wantKeyDigest := "idempotency-key-sha256:" + crypto.SHA256Hex([]byte(rotateKey))
	hasKeyDigest, hasNative, hasCommandHMAC := false, false, false
	for _, ref := range rotateApproval.EvidenceRefs {
		hasKeyDigest = hasKeyDigest || ref == wantKeyDigest
		hasNative = hasNative || ref == "surface:native"
		hasCommandHMAC = hasCommandHMAC || strings.HasPrefix(ref, "command-hmac-sha256:")
	}
	if !hasKeyDigest || !hasNative || !hasCommandHMAC {
		t.Fatalf("rotate evidence does not bind key/surface/command: %v", rotateApproval.EvidenceRefs)
	}
	plaintextHash := crypto.SHA256Hex([]byte("dual-v2"))
	if strings.Contains(rotateApproval.ToState, plaintextHash) || h.logContains(t, plaintextHash) || h.logContains(t, "dual-v2") {
		t.Fatal("approval/event log stored plaintext or a raw SHA-256 of the low-entropy secret")
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/db/password", requester, "sec08-self-approval",
		map[string]any{"action": "rotate", "request_id": rotateApproval.ID, "intent_digest": rotateApproval.IntentDigest})
	if status != http.StatusForbidden {
		t.Fatalf("self-approval status = %d body %s, want 403", status, body)
	}

	approve(approverA, "bob", "sec08-approval-bob", rotateApproval)
	approve(approverB, "carol", "sec08-approval-carol", rotateApproval)

	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", requester, rotateKey,
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
	consumed, err := h.store.GetOperationApproval(ctx, h.tenant, rotateApproval.ID)
	if err != nil {
		t.Fatalf("load consumed approval: %v", err)
	}
	if consumed.Status != store.ApprovalStatusConsumed || consumed.ConsumedEventID == "" {
		t.Fatalf("approval was not atomically consumed: %+v", consumed)
	}
	assertTargetActor(rotateApproval, rotateActor)
	// Same command + same key is the original result, never another version.
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", requester, rotateKey,
		map[string]any{"value": "dual-v2"})
	if status != http.StatusOK {
		t.Fatalf("same-key replay: status %d body %s", status, body)
	}
	replayed, err := h.store.GetSecret(ctx, h.tenant, "db/password")
	if err != nil || replayed.Version != 2 {
		t.Fatalf("same-key replay bumped secret: version=%d err=%v", replayed.Version, err)
	}
	// The raw key is authority for exactly one authenticated request body. A
	// changed value must conflict before it can reach the durable receiver.
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", requester, rotateKey,
		map[string]any{"value": "dual-v3-changed-command"})
	if status != http.StatusConflict {
		t.Fatalf("same key with changed rotate body: status %d body %s, want 409", status, body)
	}
	unchanged, err := h.store.GetSecret(ctx, h.tenant, "db/password")
	if err != nil || unchanged.Version != 2 {
		t.Fatalf("changed same-key command reached secret store: version=%d err=%v", unchanged.Version, err)
	}

	// Model a crash after event + projection commit but before the HTTP result was
	// recorded. The independently durable receipt returns the original result and
	// never asks for or spends another approval.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
			h.tenant, rotateKey)
		return err
	}); err != nil {
		t.Fatalf("simulate lost rotate response record: %v", err)
	}
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", requester, rotateKey,
		map[string]any{"value": "dual-v2"})
	if status != http.StatusOK {
		t.Fatalf("receipt reconciliation after response-record crash: status %d body %s", status, body)
	}
	reconciled, err := h.store.GetSecret(ctx, h.tenant, "db/password")
	if err != nil || reconciled.Version != 2 {
		t.Fatalf("receipt reconciliation reapplied rotate: version=%d err=%v", reconciled.Version, err)
	}

	// A fresh key creates fresh authority even for the same value/action.
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/db/password", requester, "sec08-rotate-fresh",
		map[string]any{"value": "dual-v2"})
	if status != http.StatusForbidden {
		t.Fatalf("fresh key reused spent authority: status %d body %s", status, body)
	}
	fresh := pendingApproval("rotate", 2, rotateApproval.ID)
	if fresh.ID == rotateApproval.ID || fresh.IntentDigest == rotateApproval.IntentDigest || fresh.ToState == rotateApproval.ToState {
		t.Fatalf("fresh key did not create fresh command authority: old=%+v new=%+v", rotateApproval, fresh)
	}
	if _, err := h.srv.orch.RecordOperationApprovalDecision(ctx, h.tenant, orchestrator.OperationApprovalDecision{
		RequestID: fresh.ID, IntentDigest: fresh.IntentDigest, Approver: "bob",
		Decision: store.ApprovalDecisionDeny, Reason: "abandon test command",
	}); err != nil {
		t.Fatalf("deny abandoned exact rotate before a fresh command: %v", err)
	}

	// Recovery binds the exact immutable source version and timestamp as well as
	// the current/result versions. An approval for a different point in history
	// cannot be substituted.
	source, err := h.store.GetSecretVersion(ctx, h.tenant, "db/password", 1)
	if err != nil {
		t.Fatalf("load recovery source: %v", err)
	}
	const recoverKey = "sec08-recover-exact"
	recoverBody := map[string]any{"at": source.WrittenAt.UTC().Format(time.RFC3339Nano)}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/recover/db/password", requester, recoverKey, recoverBody)
	if status != http.StatusForbidden {
		t.Fatalf("recover before approvals status=%d body=%s, want 403", status, body)
	}
	recoverActor := fencedActor()
	recoverApproval := pendingApproval("recover", 2, "")
	wantSourceVersion := "source-version:1"
	wantSourceTime := "source-written-at:" + source.WrittenAt.UTC().Format(time.RFC3339Nano)
	hasSourceVersion, hasSourceTime := false, false
	for _, evidence := range recoverApproval.EvidenceRefs {
		hasSourceVersion = hasSourceVersion || evidence == wantSourceVersion
		hasSourceTime = hasSourceTime || evidence == wantSourceTime
	}
	if !hasSourceVersion || !hasSourceTime || !strings.Contains(recoverApproval.ToState, ":recover:1:") {
		t.Fatalf("recover authority omitted exact source: %+v", recoverApproval)
	}
	approve(approverA, "bob", "sec08-recover-approval-bob", recoverApproval)
	approve(approverB, "carol", "sec08-recover-approval-carol", recoverApproval)
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/recover/db/password", requester, recoverKey, recoverBody)
	if status != http.StatusOK {
		t.Fatalf("approved recovery status=%d body=%s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/db/password", requester, nil)
	if status != http.StatusOK || json.Unmarshal(body, &rv) != nil || rv.Version != 3 || rv.Value != "dual-v1" {
		t.Fatalf("approved recovery result status=%d value=%q version=%d body=%s", status, rv.Value, rv.Version, body)
	}
	assertTargetActor(recoverApproval, recoverActor)

	const deleteKey = "sec08-delete-exact"
	status, body = secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/db/password", requester, deleteKey, nil)
	if status != http.StatusForbidden {
		t.Fatalf("delete before approvals status = %d body %s, want 403", status, body)
	}
	deleteActor := fencedActor()
	deleteApproval := pendingApproval("delete", 3, "")
	if deleteApproval.ToState == "" || !strings.HasPrefix(deleteApproval.ToState, "deleted:command-hmac-sha256:") {
		t.Fatalf("delete approval is not result-bound: %+v", deleteApproval)
	}
	approve(approverA, "bob", "sec08-delete-approval-bob", deleteApproval)
	approve(approverB, "carol", "sec08-delete-approval-carol", deleteApproval)
	status, body = secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/db/password", requester, deleteKey, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete after approvals: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/db/password", requester, nil)
	if status != http.StatusNotFound {
		t.Fatalf("read after approved delete: status %d body %s, want 404", status, body)
	}
	deletedApproval, err := h.store.GetOperationApproval(ctx, h.tenant, deleteApproval.ID)
	if err != nil || deletedApproval.Status != store.ApprovalStatusConsumed || deletedApproval.ConsumedEventID == "" {
		t.Fatalf("delete authority was not consumed with deletion: %+v err=%v", deletedApproval, err)
	}
	assertTargetActor(deleteApproval, deleteActor)
	if h.logContains(t, "dual-v1") || h.logContains(t, "dual-v2") {
		t.Error("event log leaked a dual-control secret value (AN-8)")
	}
}

// TestApplicationSecretCanonicalEventGuardsProjectionCrashGap proves the
// JetStream/SQL boundary is a command fence, not merely duplicate suppression.
// A retry of the exact plaintext command may reuse the canonical randomized
// ciphertext, while a changed body with the same raw key cannot project it.
func TestApplicationSecretCanonicalEventGuardsProjectionCrashGap(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 1
	})
	registerServedTenant(t, h, "application secret crash-gap tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "gap-alice", "secrets:read", "secrets:write")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "gap-bob", "secrets:write")
	ctx := context.Background()

	findApproval := func(name, excludeID string) store.OperationApprovalRequest {
		t.Helper()
		rows, err := h.store.ListOperationApprovals(ctx, h.tenant, "", 100)
		if err != nil {
			t.Fatalf("list %s approvals: %v", name, err)
		}
		for _, row := range rows {
			if row.ID != excludeID && row.ResourceID == "secret:"+name && row.Action == "rotate" && row.TargetVersion == 1 {
				return row
			}
		}
		t.Fatalf("missing %s rotate approval: %+v", name, rows)
		return store.OperationApprovalRequest{}
	}
	approve := func(name, key string, approval store.OperationApprovalRequest) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/"+name,
			approver, key, map[string]any{
				"action": "rotate", "request_id": approval.ID, "intent_digest": approval.IntentDigest,
			})
		if status != http.StatusOK {
			t.Fatalf("approve %s: status=%d body=%s", name, status, body)
		}
	}
	prepareProjectionGap := func(name, key, currentValue, targetValue string) store.OperationApprovalRequest {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", requester,
			map[string]any{"name": name, "value": currentValue})
		if status != http.StatusCreated {
			t.Fatalf("create %s: status=%d body=%s", name, status, body)
		}
		status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/"+name,
			requester, key, map[string]any{"value": targetValue})
		if status != http.StatusForbidden {
			t.Fatalf("open %s approval: status=%d body=%s", name, status, body)
		}
		authority := findApproval(name, "")
		approve(name, key+"-approve", authority)

		// A duplicate history version fails after Append but before the current
		// row, approval consumption, and receipt transaction can commit.
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at)
				 SELECT tenant_id, name, 2, sealed, now()
				   FROM secret_store
				  WHERE tenant_id = $1 AND name = $2`, h.tenant, name)
			return err
		}); err != nil {
			t.Fatalf("install %s projection fault: %v", name, err)
		}
		status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/"+name,
			requester, key, map[string]any{"value": targetValue})
		if status != http.StatusInternalServerError {
			t.Fatalf("%s projection fault status=%d body=%s, want 500", name, status, body)
		}
		current, err := h.store.GetSecret(ctx, h.tenant, name)
		if err != nil || current.Version != 1 {
			t.Fatalf("%s failed projection changed current: version=%d err=%v", name, current.Version, err)
		}
		fence, err := h.store.GetApplicationSecretMutationFence(ctx, h.tenant, name)
		if err != nil || fence.Actor == nil || fence.Actor.Subject != "gap-alice" || fence.EventTime.IsZero() {
			t.Fatalf("%s post-ACK fence lost exact actor/time: %+v err=%v", name, fence, err)
		}
		retained, found, err := h.log.EventByID(ctx, fence.EventID)
		if err != nil || !found || !reflect.DeepEqual(retained.Actor, fence.Actor) {
			t.Fatalf("%s retained event actor=%+v, want exact fence actor %+v; found=%t err=%v",
				name, retained.Actor, fence.Actor, found, err)
		}
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx,
				`DELETE FROM secret_store_versions
				  WHERE tenant_id = $1 AND name = $2 AND version = 2`, h.tenant, name); err != nil {
				return err
			}
			_, err := tx.Exec(ctx,
				`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`, h.tenant, key)
			return err
		}); err != nil {
			t.Fatalf("clear %s projection fault: %v", name, err)
		}
		return authority
	}

	const exactName = "canonical-exact"
	const exactKey = "canonical-gap-exact-key"
	prepareProjectionGap(exactName, exactKey, "exact-v1", "exact-v2")
	status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/"+exactName,
		requester, exactKey, map[string]any{"value": "exact-v2"})
	if status != http.StatusOK {
		t.Fatalf("exact post-append retry status=%d body=%s", status, body)
	}
	exact, err := h.store.GetSecret(ctx, h.tenant, exactName)
	if err != nil || exact.Version != 2 {
		t.Fatalf("exact retry did not reconcile canonical event: version=%d err=%v", exact.Version, err)
	}

	const changedName = "canonical-changed"
	const changedKey = "canonical-gap-changed-key"
	originalAuthority := prepareProjectionGap(changedName, changedKey, "changed-v1", "changed-v2")
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/"+changedName,
		requester, "canonical-gap-competing-key", map[string]any{"value": "changed-v2"})
	if status != http.StatusConflict {
		t.Fatalf("different key passed finalized post-append fence: status=%d body=%s, want 409", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/"+changedName,
		requester, changedKey, map[string]any{"value": "changed-v3"})
	if status != http.StatusConflict {
		t.Fatalf("changed post-append body passed finalized command fence: status=%d body=%s, want 409", status, body)
	}
	_ = originalAuthority
	changed, err := h.store.GetSecret(ctx, h.tenant, changedName)
	if err != nil || changed.Version != 1 {
		t.Fatalf("changed canonical retry mutated secret: version=%d err=%v", changed.Version, err)
	}
	var receipts int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM application_secret_mutation_receipts
			  WHERE tenant_id = $1 AND secret_name = $2 AND action = 'rotate'`, h.tenant, changedName).Scan(&receipts)
	}); err != nil {
		t.Fatalf("count changed-command receipts: %v", err)
	}
	if receipts != 0 {
		t.Fatalf("changed canonical retry wrote %d receipt(s), want zero", receipts)
	}
}

func TestApplicationSecretConcurrentKeysChooseOneDurableCommand(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 1
	})
	registerServedTenant(t, h, "application secret concurrent-command tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "race-alice", "secrets:read", "secrets:write")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "race-bob", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", requester,
		map[string]any{"name": "race/secret", "value": "race-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed concurrent secret: status=%d body=%s", status, body)
	}

	type result struct {
		key    string
		status int
		body   []byte
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for index, key := range []string{"race-key-a", "race-key-b"} {
		index, key := index, key
		go func() {
			<-start
			raw, _ := json.Marshal(map[string]any{"value": fmt.Sprintf("race-v%d", index+2)})
			req, err := http.NewRequest(http.MethodPut, h.ts.URL+"/api/v1/secrets/store/race/secret", bytes.NewReader(raw))
			if err != nil {
				results <- result{key: key, err: err}
				return
			}
			req.Header.Set("Authorization", "Bearer "+requester)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", key)
			resp, err := h.ts.Client().Do(req)
			if err != nil {
				results <- result{key: key, err: err}
				return
			}
			response, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			results <- result{key: key, status: resp.StatusCode, body: response}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent requests failed: first=%v second=%v", first.err, second.err)
	}
	byStatus := map[int]result{first.status: first, second.status: second}
	winner, winnerOK := byStatus[http.StatusForbidden]
	loser, loserOK := byStatus[http.StatusConflict]
	if !winnerOK || !loserOK {
		t.Fatalf("concurrent first-writer statuses=(%d %s),(%d %s), want one 403 claim and one 409 conflict",
			first.status, first.body, second.status, second.body)
	}
	rows, err := h.store.ListOperationApprovals(context.Background(), h.tenant, store.ApprovalStatusPending, 100)
	if err != nil {
		t.Fatal(err)
	}
	var authority store.OperationApprovalRequest
	for _, row := range rows {
		if row.ResourceID == "secret:race/secret" && row.Action == "rotate" {
			authority = row
			break
		}
	}
	if authority.ID == "" {
		t.Fatal("winning concurrent command did not create exact authority")
	}
	winnerDigest := "idempotency-key-sha256:" + crypto.SHA256Hex([]byte(winner.key))
	if !slices.Contains(authority.EvidenceRefs, winnerDigest) {
		t.Fatalf("authority belongs to neither recorded winner: winner=%q loser=%q evidence=%v", winner.key, loser.key, authority.EvidenceRefs)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/race/secret", approver,
		"race-approve", map[string]any{
			"action": "rotate", "request_id": authority.ID, "intent_digest": authority.IntentDigest,
		})
	if status != http.StatusOK {
		t.Fatalf("approve winning concurrent command: status=%d body=%s", status, body)
	}
	winnerValue := "race-v2"
	if winner.key == "race-key-b" {
		winnerValue = "race-v3"
	}
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/race/secret", requester,
		winner.key, map[string]any{"value": winnerValue})
	if status != http.StatusOK {
		t.Fatalf("winning command did not finalize: status=%d body=%s", status, body)
	}
	current, err := h.store.GetSecret(context.Background(), h.tenant, "race/secret")
	if err != nil || current.Version != 2 {
		t.Fatalf("winning command result=%+v err=%v", current, err)
	}
	if err := h.srv.proj.Rebuild(context.Background(), h.log); err != nil {
		t.Fatalf("full rebuild after concurrent keys: %v", err)
	}
	current, err = h.store.GetSecret(context.Background(), h.tenant, "race/secret")
	if err != nil || current.Version != 2 {
		t.Fatalf("rebuild after concurrent keys changed result=%+v err=%v", current, err)
	}
}

// TestVaultOverwriteRequiresExactSecretApproval proves the Vault/OpenBao KV shim
// cannot bypass the native one-shot authority. Initial create remains a create;
// an overwrite is the same sealed rotate command with surface=vault evidence.
func TestVaultOverwriteRequiresExactSecretApproval(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 1
	})
	registerServedTenant(t, h, "served Vault application-secret tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "vault-alice", "secrets:read", "secrets:write")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "vault-bob", "secrets:write")

	vaultRequest := func(key string, value map[string]string) (int, []byte) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"data": value})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPut, h.ts.URL+"/v1/secret/data/exact", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Vault-Token", requester)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}

	if status, body := vaultRequest("vault-exact-create", map[string]string{"fixture_value": "vault-low-entropy-v1"}); status != http.StatusOK {
		t.Fatalf("Vault create status=%d body=%s", status, body)
	}
	const overwriteKey = "vault-exact-overwrite"
	if status, body := vaultRequest(overwriteKey, map[string]string{"fixture_value": "vault-low-entropy-v2"}); status != http.StatusForbidden {
		t.Fatalf("Vault overwrite before approval status=%d body=%s", status, body)
	}
	vaultFence, err := h.store.GetApplicationSecretMutationFence(context.Background(), h.tenant, "exact")
	if err != nil || vaultFence.Actor == nil || vaultFence.Actor.Subject != "vault-alice" {
		t.Fatalf("Vault overwrite fence actor=%+v err=%v", vaultFence.Actor, err)
	}
	wantVaultActor := &events.Actor{
		Subject: vaultFence.Actor.Subject, Roles: append([]string(nil), vaultFence.Actor.Roles...),
	}
	rows, err := h.store.ListOperationApprovals(context.Background(), h.tenant, store.ApprovalStatusPending, 100)
	if err != nil {
		t.Fatal(err)
	}
	var exact store.OperationApprovalRequest
	for _, row := range rows {
		if row.ResourceID == "secret:exact" && row.Action == "rotate" && row.TargetVersion == 1 {
			exact = row
			break
		}
	}
	if exact.ID == "" || exact.Requester != "vault-alice" || !strings.Contains(exact.ToState, "command-hmac-sha256:") {
		t.Fatalf("Vault overwrite did not open exact rotate authority: %+v", exact)
	}
	hasVaultSurface := false
	for _, evidence := range exact.EvidenceRefs {
		hasVaultSurface = hasVaultSurface || evidence == "surface:vault"
	}
	if !hasVaultSurface {
		t.Fatalf("Vault overwrite approval omitted surface binding: %v", exact.EvidenceRefs)
	}
	if h.logContains(t, "vault-low-entropy-v2") || h.logContains(t, crypto.SHA256Hex([]byte("vault-low-entropy-v2"))) {
		t.Fatal("Vault approval/event stored plaintext or its raw low-entropy SHA-256")
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/exact", approver,
		"vault-exact-approve", map[string]any{
			"action": "rotate", "request_id": exact.ID, "intent_digest": exact.IntentDigest,
		})
	if status != http.StatusOK {
		t.Fatalf("approve Vault overwrite status=%d body=%s", status, body)
	}
	if status, body = vaultRequest(overwriteKey, map[string]string{"fixture_value": "vault-low-entropy-v2"}); status != http.StatusOK {
		t.Fatalf("approved Vault overwrite status=%d body=%s", status, body)
	}
	current, err := h.store.GetSecret(context.Background(), h.tenant, "exact")
	if err != nil || current.Version != 2 {
		t.Fatalf("Vault overwrite current version=%d err=%v, want 2", current.Version, err)
	}
	spent, err := h.store.GetOperationApproval(context.Background(), h.tenant, exact.ID)
	if err != nil || spent.Status != store.ApprovalStatusConsumed || spent.ConsumedEventID == "" {
		t.Fatalf("Vault overwrite authority not consumed atomically: %+v err=%v", spent, err)
	}
	vaultEvent, found, err := h.log.EventByID(context.Background(), spent.ConsumedEventID)
	if err != nil || !found || !reflect.DeepEqual(vaultEvent.Actor, wantVaultActor) {
		t.Fatalf("Vault target actor=%+v, want exact fence actor %+v; found=%t err=%v",
			vaultEvent.Actor, wantVaultActor, found, err)
	}
	if status, body = vaultRequest(overwriteKey, map[string]string{"fixture_value": "vault-changed-command"}); status != http.StatusConflict {
		t.Fatalf("Vault same key with changed body status=%d body=%s, want 409", status, body)
	}
	current, err = h.store.GetSecret(context.Background(), h.tenant, "exact")
	if err != nil || current.Version != 2 {
		t.Fatalf("changed Vault command reached secret store: version=%d err=%v", current.Version, err)
	}

	ctx := context.Background()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
			h.tenant, overwriteKey)
		return err
	}); err != nil {
		t.Fatalf("simulate lost Vault response record: %v", err)
	}
	if status, body = vaultRequest(overwriteKey, map[string]string{"fixture_value": "vault-low-entropy-v2"}); status != http.StatusOK {
		t.Fatalf("Vault receipt reconciliation status=%d body=%s", status, body)
	}
	current, err = h.store.GetSecret(ctx, h.tenant, "exact")
	if err != nil || current.Version != 2 {
		t.Fatalf("Vault receipt reconciliation reapplied overwrite: version=%d err=%v", current.Version, err)
	}
}

func TestApplicationSecretMutationsFailClosedWithoutEventLog(t *testing.T) {
	secretKEK, err := kek.LoadOrCreate(secretsTestKEKPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secretKEK.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		d.KEK = secretKEK
	})
	registerServedTenant(t, h, "application secret no-log tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	for _, name := range []string{"nolog-rotate", "nolog-recover", "nolog-delete"} {
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
			map[string]any{"name": name, "value": "unchanged-v1"})
		if status != http.StatusCreated {
			t.Fatalf("seed %s: status=%d body=%s", name, status, body)
		}
	}
	recoverySource, err := h.store.GetSecretVersion(context.Background(), h.tenant, "nolog-recover", 1)
	if err != nil {
		t.Fatal(err)
	}

	backend := h.srv.buildSecretsBackend(Deps{Store: h.store, KEK: secretKEK})
	if backend.EventLog != nil {
		t.Fatal("no-log regression accidentally retained an event log")
	}
	noLog := api.New(h.store, h.srv.idem, h.srv.orch,
		api.WithInsecureHeaderResolver(), api.WithSecrets(backend))
	ts := httptest.NewServer(noLog)
	t.Cleanup(ts.Close)

	request := func(method, path, key string, body any) (int, []byte) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			raw, marshalErr := json.Marshal(body)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			reader = bytes.NewReader(raw)
		}
		req, requestErr := http.NewRequest(method, ts.URL+path, reader)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("X-Tenant-ID", h.tenant)
		req.Header.Set("X-Roles", "admin")
		req.Header.Set("X-Subject", "no-log-admin")
		req.Header.Set("Idempotency-Key", key)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, requestErr := ts.Client().Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		defer func() { _ = resp.Body.Close() }()
		response, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, response
	}

	cases := []struct {
		name, method, path, key string
		body                    any
	}{
		{name: "create", method: http.MethodPost, path: "/api/v1/secrets/store", key: "nolog-create-key",
			body: map[string]any{"name": "nolog-create", "value": "must-not-materialize"}},
		{name: "rotate", method: http.MethodPut, path: "/api/v1/secrets/store/nolog-rotate", key: "nolog-rotate-key",
			body: map[string]any{"value": "must-not-rotate"}},
		{name: "recover", method: http.MethodPost, path: "/api/v1/secrets/store/recover/nolog-recover", key: "nolog-recover-key",
			body: map[string]any{"at": recoverySource.WrittenAt.UTC().Format(time.RFC3339Nano)}},
		{name: "delete", method: http.MethodDelete, path: "/api/v1/secrets/store/nolog-delete", key: "nolog-delete-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := request(tc.method, tc.path, tc.key, tc.body)
			if status != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s, want fail-closed 500", status, body)
			}
			secretName := "nolog-" + tc.name
			fence, err := h.store.GetApplicationSecretMutationFence(context.Background(), h.tenant, secretName)
			if err != nil || fence.Actor == nil || fence.Actor.Subject != "no-log-admin" ||
				!reflect.DeepEqual(fence.Actor.Roles, []string{"admin"}) || fence.EventTime.IsZero() {
				t.Fatalf("%s finalized fence actor=%+v time=%v err=%v", tc.name, fence.Actor, fence.EventTime, err)
			}
		})
	}
	if _, err := h.store.GetSecret(context.Background(), h.tenant, "nolog-create"); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("no-log create materialized primary state: %v", err)
	}
	for _, name := range []string{"nolog-rotate", "nolog-recover", "nolog-delete"} {
		current, err := h.store.GetSecret(context.Background(), h.tenant, name)
		if err != nil || current.Version != 1 {
			t.Fatalf("no-log %s changed primary state: version=%d err=%v", name, current.Version, err)
		}
	}
}

func TestApplicationSecretCreateResponseLossReplaysReceiptWithoutSealer(t *testing.T) {
	secretKEK, err := kek.LoadOrCreate(secretsTestKEKPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secretKEK.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		d.KEK = secretKEK
	})
	registerServedTenant(t, h, "application secret response-loss tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	const nativeKey = "native-create-response-gap"
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, nativeKey,
		map[string]any{"name": "response-gap-native", "value": "native-v1"})
	if status != http.StatusCreated {
		t.Fatalf("native create: status=%d body=%s", status, body)
	}
	vaultCreate := func(harness *servedHarness, key, value string) (int, []byte) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"data": map[string]string{"fixture_value": value}})
		req, err := http.NewRequest(http.MethodPut, harness.ts.URL+"/v1/secret/data/response-gap-vault", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Vault-Token", token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err := harness.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		response, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, response
	}
	const vaultKey = "vault-create-response-gap"
	status, body = vaultCreate(h, vaultKey, "vault-v1")
	if status != http.StatusOK {
		t.Fatalf("Vault create: status=%d body=%s", status, body)
	}

	type receiptResult struct {
		version              int
		createdAt, updatedAt time.Time
	}
	receiptFor := func(name string) receiptResult {
		t.Helper()
		var result receiptResult
		if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(),
				`SELECT result_version, result_created_at, result_updated_at
				   FROM application_secret_mutation_receipts
				  WHERE tenant_id = $1 AND secret_name = $2 AND action = 'create'`,
				h.tenant, name).Scan(&result.version, &result.createdAt, &result.updatedAt)
		}); err != nil {
			t.Fatalf("load %s create receipt: %v", name, err)
		}
		return result
	}
	nativeBefore := receiptFor("response-gap-native")
	vaultBefore := receiptFor("response-gap-vault")
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = ANY($2)`,
			h.tenant, []string{nativeKey, vaultKey})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	restarted, err := Build(context.Background(), Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: secretKEK, TenantCrypto: failingTenantCipherAccess{},
		EnableSecretsAPI: true,
	})
	if err != nil {
		t.Fatalf("restart with unavailable sealer: %v", err)
	}
	ts := httptest.NewServer(restarted.Handler())
	t.Cleanup(ts.Close)
	h2 := &servedHarness{ts: ts, store: h.store, log: h.log, tenant: h.tenant, srv: restarted}
	status, body = secretsReqKey(t, h2, http.MethodPost, "/api/v1/secrets/store", token, nativeKey,
		map[string]any{"name": "response-gap-native", "value": "native-v1"})
	if status != http.StatusCreated {
		t.Fatalf("native create receipt replay attempted sealing: status=%d body=%s", status, body)
	}
	status, body = vaultCreate(h2, vaultKey, "vault-v1")
	if status != http.StatusOK {
		t.Fatalf("Vault create receipt replay became overwrite/seal: status=%d body=%s", status, body)
	}
	if status, body = secretsReqKey(t, h2, http.MethodPost, "/api/v1/secrets/store", token, nativeKey,
		map[string]any{"name": "response-gap-native", "value": "native-changed"}); status != http.StatusConflict {
		t.Fatalf("native changed create replay status=%d body=%s, want 409", status, body)
	}
	if status, body = vaultCreate(h2, vaultKey, "vault-changed"); status != http.StatusConflict {
		t.Fatalf("Vault changed create replay status=%d body=%s, want 409", status, body)
	}
	for name, before := range map[string]receiptResult{
		"response-gap-native": nativeBefore, "response-gap-vault": vaultBefore,
	} {
		after := receiptFor(name)
		if after.version != 1 || after != before {
			t.Fatalf("%s create receipt changed across response loss: before=%+v after=%+v", name, before, after)
		}
		current, err := h.store.GetSecret(context.Background(), h.tenant, name)
		if err != nil || current.Version != 1 {
			t.Fatalf("%s create replay changed version: %+v err=%v", name, current, err)
		}
	}
	eventCounts := map[string]int{}
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.Type != projections.EventApplicationSecretCreated ||
			event.SchemaVersion != projections.ApplicationSecretMutationSchemaVersion {
			return nil
		}
		var payload projections.ApplicationSecretMutation
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		eventCounts[payload.Name]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if eventCounts["response-gap-native"] != 1 || eventCounts["response-gap-vault"] != 1 {
		t.Fatalf("response-loss create duplicated events: %v", eventCounts)
	}
}

func TestApplicationSecretRestartIsolatesTenantCustodyAndRetries(t *testing.T) {
	const tenantB = "22222222-2222-2222-2222-222222222222"
	secretKEK, err := kek.LoadOrCreate(secretsTestKEKPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secretKEK.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		d.KEK = secretKEK
		d.RequireApproval = true
		d.RequiredApprovals = 1
		// Model a crash after Claim but before the exact approval request exists.
		// The claim-time decision and sealed requester must be enough for restart.
		d.APIOptions = append(d.APIOptions, api.WithMutationGate(api.MutationGate{RequireApproval: true}))
	})
	registerServedTenant(t, h, "application secret custody tenant A")
	requesterA := seedScopedTokenSubject(t, h.store, h.tenant, "custody-alice", "secrets:read", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", requesterA,
		map[string]any{"name": "custody-a", "value": "tenant-a-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed tenant A: status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/custody-a", requesterA,
		"custody-a-rotate", map[string]any{"value": "tenant-a-v2"})
	if status != http.StatusForbidden {
		t.Fatalf("tenant A unbound claim status=%d body=%s, want 403", status, body)
	}
	fenceA, err := h.store.GetApplicationSecretMutationFence(context.Background(), h.tenant, "custody-a")
	if err != nil {
		t.Fatal(err)
	}
	if !fenceA.ApprovalRequired || fenceA.Approval != nil || fenceA.EventTime.IsZero() == false || len(fenceA.RequesterSealed) == 0 {
		t.Fatalf("tenant A fence did not persist claim-time approval + sealed requester: %+v", fenceA)
	}
	if fenceA.Actor == nil || fenceA.Actor.Subject != "custody-alice" {
		t.Fatalf("tenant A fence lost its exact request actor: %+v", fenceA.Actor)
	}
	wantActorA := &events.Actor{Subject: fenceA.Actor.Subject, Roles: append([]string(nil), fenceA.Actor.Roles...)}
	if err := h.store.UpsertTenant(context.Background(), store.Tenant{
		TenantID: h.tenant, Name: "custody-tenant-a",
	}); err != nil {
		t.Fatalf("register tenant A lifecycle read model: %v", err)
	}

	if _, err := h.store.CreateOwner(context.Background(), store.Owner{
		TenantID: tenantB, Kind: store.OwnerWorkload, Name: "custody-tenant-b",
	}); err != nil {
		t.Fatalf("register tenant B: %v", err)
	}
	if err := h.store.UpsertTenant(context.Background(), store.Tenant{
		TenantID: tenantB, Name: "custody-tenant-b",
	}); err != nil {
		t.Fatalf("register tenant B lifecycle read model: %v", err)
	}
	// Tenant B crashes after a no-approval create fence is finalized but before
	// Append. Restart with approval enabled must still obey the persisted false
	// decision and finish it without inventing approval authority.
	backendB := h.srv.buildSecretsBackend(Deps{Store: h.store, KEK: secretKEK})
	noLogB := api.New(h.store, h.srv.idem, h.srv.orch,
		api.WithInsecureHeaderResolver(), api.WithSecrets(backendB),
		api.WithMutationGate(api.MutationGate{}))
	rawB, _ := json.Marshal(map[string]any{"name": "custody-b", "value": "tenant-b-v1"})
	reqB := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/store", bytes.NewReader(rawB))
	reqB.Header.Set("Content-Type", "application/json")
	reqB.Header.Set("X-Tenant-ID", tenantB)
	reqB.Header.Set("X-Roles", "admin")
	reqB.Header.Set("X-Subject", "custody-bob")
	reqB.Header.Set("Idempotency-Key", "custody-b-create")
	recB := httptest.NewRecorder()
	noLogB.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusInternalServerError {
		t.Fatalf("tenant B crash fixture status=%d body=%s, want 500", recB.Code, recB.Body.Bytes())
	}
	fenceB, err := h.store.GetApplicationSecretMutationFence(context.Background(), tenantB, "custody-b")
	if err != nil {
		t.Fatal(err)
	}
	if fenceB.ApprovalRequired || fenceB.EventTime.IsZero() {
		t.Fatalf("tenant B fence did not persist non-approval finalized admission: %+v", fenceB)
	}
	if fenceB.Actor == nil || fenceB.Actor.Subject != "custody-bob" {
		t.Fatalf("tenant B fence lost its exact request actor: %+v", fenceB.Actor)
	}
	wantActorB := &events.Actor{Subject: fenceB.Actor.Subject, Roles: append([]string(nil), fenceB.Actor.Roles...)}

	access := &selectivelyBlockedTenantAccess{
		wrapper: secretKEK, blocked: map[string]bool{h.tenant: true},
	}
	restarted, err := Build(context.Background(), Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: secretKEK, TenantCrypto: access,
		EnableSecretsAPI: true, RequireApproval: true, RequiredApprovals: 1,
	})
	if err != nil {
		t.Fatalf("tenant A custody outage failed whole startup: %v", err)
	}
	secretB, err := h.store.GetSecret(context.Background(), tenantB, "custody-b")
	if err != nil || secretB.Version != 1 {
		t.Fatalf("tenant A outage prevented tenant B finalization: secret=%+v err=%v", secretB, err)
	}
	if _, err := h.store.GetApplicationSecretMutationFence(context.Background(), tenantB, "custody-b"); !store.IsNotFound(err) {
		t.Fatalf("tenant B finalized fence remains: %v", err)
	}
	var eventActorB *events.Actor
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.Type != projections.EventApplicationSecretCreated || event.TenantID != tenantB {
			return nil
		}
		var payload projections.ApplicationSecretMutation
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		if payload.Name == "custody-b" {
			eventActorB = event.Actor
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(eventActorB, wantActorB) {
		t.Fatalf("tenant B recovered event actor=%+v, want exact fence actor %+v", eventActorB, wantActorB)
	}
	secretA, err := h.store.GetSecret(context.Background(), h.tenant, "custody-a")
	if err != nil || secretA.Version != 1 {
		t.Fatalf("custody-blocked tenant A mutated: secret=%+v err=%v", secretA, err)
	}
	if restarted.api.ApplicationSecretMutationReconcileBlockedCount() != 1 {
		t.Fatalf("blocked count=%d, want exactly tenant A's one fence",
			restarted.api.ApplicationSecretMutationReconcileBlockedCount())
	}
	ready, checks := restarted.readiness.Evaluate(context.Background())
	if ready || !strings.Contains(checks["application_secret_reconciliation"], "custody") {
		t.Fatalf("custody-blocked startup readiness=%t checks=%v, want degraded evidence", ready, checks)
	}

	metrics := httptest.NewRecorder()
	restarted.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	blockedMetricLines, degradedMetricLines := 0, 0
	for _, line := range strings.Split(metrics.Body.String(), "\n") {
		if strings.HasPrefix(line, "trstctl_application_secret_reconcile_blocked") {
			blockedMetricLines++
			if strings.Contains(line, "{") || strings.Contains(line, h.tenant) || strings.Contains(line, tenantB) || strings.Contains(line, "custody-a") {
				t.Fatalf("application-secret reconcile metric leaks cardinality labels: %q", line)
			}
		}
		if strings.HasPrefix(line, "trstctl_application_secret_reconcile_degraded") {
			degradedMetricLines++
			if strings.Contains(line, "{") || !strings.HasSuffix(line, " 1") {
				t.Fatalf("application-secret degraded metric is labeled or not set: %q", line)
			}
		}
	}
	if blockedMetricLines != 1 || degradedMetricLines != 1 {
		t.Fatalf("application-secret metric sample lines blocked=%d degraded=%d body=%s",
			blockedMetricLines, degradedMetricLines, metrics.Body.String())
	}

	access.setBlocked(h.tenant, false)
	restarted.reconcileApplicationSecretMutationsOnce(context.Background())
	if err := restarted.api.ApplicationSecretMutationReconcileHealth(context.Background()); err != nil {
		t.Fatalf("readiness did not clear after custody returned: %v", err)
	}
	ready, checks = restarted.readiness.Evaluate(context.Background())
	if !ready {
		t.Fatalf("readiness remained degraded after custody returned: %v", checks)
	}
	fenceA, err = h.store.GetApplicationSecretMutationFence(context.Background(), h.tenant, "custody-a")
	if err != nil || fenceA.Approval == nil || len(fenceA.RequesterSealed) != 0 || !fenceA.EventTime.IsZero() {
		t.Fatalf("custody recovery did not resume the exact approval without bypassing it: %+v err=%v", fenceA, err)
	}
	if !reflect.DeepEqual(fenceA.Actor, wantActorA) {
		t.Fatalf("custody recovery changed tenant A actor: got=%+v want=%+v", fenceA.Actor, wantActorA)
	}
	if currentA, err := h.store.GetSecret(context.Background(), h.tenant, "custody-a"); err != nil || currentA.Version != 1 {
		t.Fatalf("approval-required tenant A command bypassed after custody recovery: %+v err=%v", currentA, err)
	}

	// A non-custody recovery failure must remain observable too. Corrupt only the
	// fence's integrity digest, run one pass, and prove readiness exposes a generic
	// degraded bit without tenant/name/raw-error contents. A later clean pass clears it.
	goodPayloadDigest := crypto.SHA256Hex(fenceA.Payload)
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`UPDATE application_secret_mutation_fences SET payload_sha256 = $3
			  WHERE tenant_id = $1 AND secret_name = $2`, h.tenant, "custody-a", strings.Repeat("f", 64))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	restarted.reconcileApplicationSecretMutationsOnce(context.Background())
	healthErr := restarted.api.ApplicationSecretMutationReconcileHealth(context.Background())
	if healthErr == nil || strings.Contains(healthErr.Error(), h.tenant) || strings.Contains(healthErr.Error(), "custody-a") ||
		strings.Contains(healthErr.Error(), "digest") {
		t.Fatalf("structural recovery health was green or leaked raw detail: %v", healthErr)
	}
	ready, checks = restarted.readiness.Evaluate(context.Background())
	if ready || checks["application_secret_reconciliation"] != healthErr.Error() {
		t.Fatalf("structural recovery failure did not degrade readiness generically: %v", checks)
	}
	if !restarted.api.ApplicationSecretMutationReconcileDegraded() {
		t.Fatal("structural recovery failure left degraded metric bit clear")
	}
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`UPDATE application_secret_mutation_fences SET payload_sha256 = $3
			  WHERE tenant_id = $1 AND secret_name = $2`, h.tenant, "custody-a", goodPayloadDigest)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	restarted.reconcileApplicationSecretMutationsOnce(context.Background())
	if err := restarted.api.ApplicationSecretMutationReconcileHealth(context.Background()); err != nil ||
		restarted.api.ApplicationSecretMutationReconcileDegraded() {
		t.Fatalf("clean recovery pass did not clear structural degradation: %v", err)
	}
}

func TestApplicationSecretLegacyActorlessFenceStartsDegradedAndLiveRetryFailsClosed(t *testing.T) {
	secretKEK, err := kek.LoadOrCreate(secretsTestKEKPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secretKEK.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		d.KEK = secretKEK
	})
	const (
		name    = "legacy/actorless"
		key     = "legacy-actorless-create"
		subject = "legacy-alice"
	)
	token := seedScopedTokenSubject(t, h.store, h.tenant, subject, "secrets:read", "secrets:write")
	if err := h.store.UpsertTenant(context.Background(), store.Tenant{
		TenantID: h.tenant, Name: "legacy-actorless-tenant",
	}); err != nil {
		t.Fatal(err)
	}

	// Model a pre-0152 crash: the command crossed Finalize but its process had no
	// broker, then an upgrade encounters the historic row without actor columns.
	backend := h.srv.buildSecretsBackend(Deps{Store: h.store, KEK: secretKEK})
	noLog := api.New(h.store, h.srv.idem, h.srv.orch,
		api.WithInsecureHeaderResolver(), api.WithSecrets(backend))
	raw, _ := json.Marshal(map[string]any{"name": name, "value": "legacy-v1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/store", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", h.tenant)
	req.Header.Set("X-Subject", subject)
	req.Header.Set("X-Roles", "admin")
	req.Header.Set("Idempotency-Key", key)
	rec := httptest.NewRecorder()
	noLog.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("legacy crash fixture status=%d body=%s, want 500", rec.Code, rec.Body.Bytes())
	}
	before, err := h.store.GetApplicationSecretMutationFence(context.Background(), h.tenant, name)
	if err != nil || before.EventTime.IsZero() || before.Actor == nil {
		t.Fatalf("legacy crash fixture did not finalize an attributed fence: %+v err=%v", before, err)
	}
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(),
			`UPDATE application_secret_mutation_fences
			    SET actor = NULL, actor_subject_ref = NULL
			  WHERE tenant_id = $1 AND secret_name = $2`, h.tenant, name); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(),
			`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`, h.tenant, key)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	restarted, err := Build(context.Background(), Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: secretKEK, EnableSecretsAPI: true,
	})
	if err != nil {
		t.Fatalf("legacy actorless fence prevented safe startup: %v", err)
	}
	if restarted.api.ApplicationSecretMutationReconcileBlockedCount() != 1 ||
		!restarted.api.ApplicationSecretMutationReconcileDegraded() {
		t.Fatalf("legacy actorless startup health blocked=%d degraded=%t, want 1/true",
			restarted.api.ApplicationSecretMutationReconcileBlockedCount(),
			restarted.api.ApplicationSecretMutationReconcileDegraded())
	}
	healthErr := restarted.api.ApplicationSecretMutationReconcileHealth(context.Background())
	if healthErr == nil || !strings.Contains(healthErr.Error(), "legacy_actor_unavailable") ||
		strings.Contains(healthErr.Error(), h.tenant) || strings.Contains(healthErr.Error(), name) ||
		strings.Contains(healthErr.Error(), subject) {
		t.Fatalf("legacy actorless health is green, unclassified, or leaks cardinality: %v", healthErr)
	}
	ready, checks := restarted.readiness.Evaluate(context.Background())
	if ready || checks["application_secret_reconciliation"] != healthErr.Error() {
		t.Fatalf("legacy actorless startup did not degrade readiness: %v", checks)
	}
	metrics := httptest.NewRecorder()
	restarted.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	blockedSample, degradedSample := "", ""
	for _, line := range strings.Split(metrics.Body.String(), "\n") {
		if strings.HasPrefix(line, "trstctl_application_secret_reconcile_blocked") {
			blockedSample = line
		}
		if strings.HasPrefix(line, "trstctl_application_secret_reconcile_degraded") {
			degradedSample = line
		}
	}
	if !strings.HasSuffix(blockedSample, " 1") || !strings.HasSuffix(degradedSample, " 1") ||
		strings.Contains(blockedSample, "{") || strings.Contains(degradedSample, "{") ||
		strings.Contains(blockedSample+degradedSample, h.tenant) ||
		strings.Contains(blockedSample+degradedSample, name) ||
		strings.Contains(blockedSample+degradedSample, subject) {
		t.Fatalf("legacy actorless metrics are absent, mislabeled, or leak cardinality: %q / %q",
			blockedSample, degradedSample)
	}
	after, err := h.store.GetApplicationSecretMutationFence(context.Background(), h.tenant, name)
	if err != nil || after.Actor != nil || !after.EventTime.Equal(before.EventTime) {
		t.Fatalf("blocked startup changed or released legacy fence: before=%+v after=%+v err=%v", before, after, err)
	}
	if _, err := h.store.GetSecret(context.Background(), h.tenant, name); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("blocked startup materialized legacy secret: %v", err)
	}

	ts := httptest.NewServer(restarted.Handler())
	t.Cleanup(ts.Close)
	h2 := &servedHarness{ts: ts, store: h.store, log: h.log, tenant: h.tenant, srv: restarted}
	status, body := secretsReqKey(t, h2, http.MethodPost, "/api/v1/secrets/store", token, key,
		map[string]any{"name": name, "value": "legacy-v1"})
	if status != http.StatusConflict {
		t.Fatalf("authenticated live legacy retry status=%d body=%s, want 409", status, body)
	}
	eventCount := 0
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.Type != projections.EventApplicationSecretCreated {
			return nil
		}
		var payload projections.ApplicationSecretMutation
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		if payload.Name == name {
			eventCount++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if eventCount != 0 {
		t.Fatalf("legacy actorless startup/live retry published %d target event(s), want zero", eventCount)
	}
}

func TestApplicationSecretRequiredFenceSurvivesApprovalDisabledRestart(t *testing.T) {
	secretKEK, err := kek.LoadOrCreate(secretsTestKEKPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secretKEK.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		d.KEK = secretKEK
		d.RequireApproval = true
		d.RequiredApprovals = 1
		d.APIOptions = append(d.APIOptions, api.WithMutationGate(api.MutationGate{RequireApproval: true}))
	})
	registerServedTenant(t, h, "application secret approval-restart tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "flip-alice", "secrets:read", "secrets:write")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "flip-bob", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", requester,
		map[string]any{"name": "flip/required", "value": "flip-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed required flip: status=%d body=%s", status, body)
	}
	const rotateKey = "required-before-disabled-restart"
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/flip/required", requester,
		rotateKey, map[string]any{"value": "flip-v2"})
	if status != http.StatusForbidden {
		t.Fatalf("claim required fence: status=%d body=%s", status, body)
	}
	claimed, err := h.store.GetApplicationSecretMutationFence(context.Background(), h.tenant, "flip/required")
	if err != nil || claimed.Actor == nil || claimed.Actor.Subject != "flip-alice" {
		t.Fatalf("claim-time required fence actor=%+v err=%v", claimed.Actor, err)
	}
	wantActor := &events.Actor{Subject: claimed.Actor.Subject, Roles: append([]string(nil), claimed.Actor.Roles...)}
	if err := h.store.UpsertTenant(context.Background(), store.Tenant{TenantID: h.tenant, Name: "flip-tenant"}); err != nil {
		t.Fatal(err)
	}

	restarted, err := Build(context.Background(), Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: secretKEK, EnableSecretsAPI: true,
		RequireApproval: false, RequiredApprovals: 1,
	})
	if err != nil {
		t.Fatalf("approval-disabled restart: %v", err)
	}
	h2 := &servedHarness{srv: restarted, store: h.store, log: h.log, tenant: h.tenant}
	ts := httptest.NewServer(restarted.Handler())
	t.Cleanup(ts.Close)
	h2.ts = ts
	fence, err := h.store.GetApplicationSecretMutationFence(context.Background(), h.tenant, "flip/required")
	if err != nil || !fence.ApprovalRequired || fence.Approval == nil || !fence.EventTime.IsZero() {
		t.Fatalf("disabled restart bypassed or lost claim-time approval: %+v err=%v", fence, err)
	}
	if !reflect.DeepEqual(fence.Actor, wantActor) {
		t.Fatalf("disabled restart changed required fence actor: got=%+v want=%+v", fence.Actor, wantActor)
	}
	current, err := h.store.GetSecret(context.Background(), h.tenant, "flip/required")
	if err != nil || current.Version != 1 {
		t.Fatalf("required command finalized nil on disabled restart: %+v err=%v", current, err)
	}
	// Unrelated claim-time no-approval work still proceeds.
	status, body = secretsReqKey(t, h2, http.MethodPost, "/api/v1/secrets/store", requester,
		"flip-unrelated-create", map[string]any{"name": "flip/unrelated", "value": "ok"})
	if status != http.StatusCreated {
		t.Fatalf("unrelated no-approval work blocked by required fence: status=%d body=%s", status, body)
	}

	request, err := h.store.GetOperationApproval(context.Background(), h.tenant, fence.Approval.RequestID)
	if err != nil || request.Status != store.ApprovalStatusPending {
		t.Fatalf("restart did not resume exact pending authority: %+v err=%v", request, err)
	}
	status, body = secretsReqKey(t, h2, http.MethodPost, "/api/v1/secrets/store/approvals/flip/required", approver,
		"flip-approve", map[string]any{
			"action": "rotate", "request_id": request.ID, "intent_digest": request.IntentDigest,
		})
	if status != http.StatusOK {
		t.Fatalf("approve after disabled restart: status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h2, http.MethodPut, "/api/v1/secrets/store/flip/required", requester,
		rotateKey, map[string]any{"value": "flip-v2"})
	if status != http.StatusOK {
		t.Fatalf("exact required retry after disabled restart: status=%d body=%s", status, body)
	}
	current, err = h.store.GetSecret(context.Background(), h.tenant, "flip/required")
	if err != nil || current.Version != 2 {
		t.Fatalf("approved exact command after disabled restart: %+v err=%v", current, err)
	}
	request, err = h.store.GetOperationApproval(context.Background(), h.tenant, request.ID)
	if err != nil || request.Status != store.ApprovalStatusConsumed || request.ConsumedEventID == "" {
		t.Fatalf("claim-time required authority was not consumed exactly: %+v err=%v", request, err)
	}
	var targetActor *events.Actor
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.ID == request.ConsumedEventID {
			targetActor = event.Actor
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(targetActor, wantActor) {
		t.Fatalf("approved restart event actor=%+v, want exact fence actor %+v", targetActor, wantActor)
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

	// #nosec G101 -- fabricated STS exchange fixture; no real credential (CWE-798)
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
	registerServedTenant(t, h, "tenant A secret-isolation tenant")
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
