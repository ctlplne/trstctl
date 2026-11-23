// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/historycontinuity"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/storetest"
	"trstctl.com/trstctl/internal/tenantseal"
)

// v3OAuthLab is an RFC 6749 client-credentials authorization server with an
// RFC 7009 revocation endpoint, and a resource server that accepts its
// unrevoked, unexpired tokens. It counts every call to the revocation
// endpoint per token, so the test can tell "the provider was never asked" from
// "the provider refused".
type v3OAuthLab struct {
	mu          sync.Mutex
	tokens      map[string]time.Time
	revoked     map[string]bool
	revokeCalls map[string]int
}

func (l *v3OAuthLab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.URL.Path == "/orders" {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		expires, known := l.tokens[token]
		if !ok || !known || l.revoked[token] || time.Now().After(expires) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"orders":[]}`))
		return
	}
	if id, secret, ok := r.BasicAuth(); !ok || id != "trstctl-leases" || secret != "lab-client-secret" { // #nosec G101 -- fabricated lab client secret (CWE-798)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	case "/token":
		raw, err := crypto.RandomBytes(16)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		token := hex.EncodeToString(raw)
		l.tokens[token] = time.Now().Add(5 * time.Minute)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 300, "scope": r.PostForm.Get("scope")})
	case "/revoke":
		token := r.PostForm.Get("token")
		l.revokeCalls[token]++
		l.revoked[token] = true
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (l *v3OAuthLab) state(token string) (revoked bool, calls int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.revoked[token], l.revokeCalls[token]
}

// syncBuffer is a goroutine-safe log sink.
type v3SyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *v3SyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *v3SyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestV3PendingOAuthRevocationIsStrandedByTenantKeyDomainMigration is the
// served end-to-end form of R1 review LI-4-L3 (verifier V3). Two tenants each
// hold an OAuth lease from an authorization server with an RFC 7009 revocation
// endpoint, and each revokes it while the provider revocation is still
// pending (the outbox worker has not yet delivered it). Tenant A then migrates
// to its own key domain through the served route; tenant B stays on the
// deployment KEK (the paired control). When the worker runs, tenant B's token
// is revoked at the authorization server; tenant A's revocation can no longer
// open the credential it must present, so the provider is never asked and the
// token stays valid at the resource server.
func TestV3PendingOAuthRevocationIsStrandedByTenantKeyDomainMigration(t *testing.T) {
	ctx := context.Background()
	const tenantB = "b3b3b3b3-0000-4000-8000-0000000000b3"

	logs := &v3SyncBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		slog.SetDefault(previous)
		if !t.Failed() {
			return
		}
		shown := 0
		for _, line := range strings.Split(logs.String(), "\n") {
			if shown < 40 && (strings.Contains(line, "level=WARN") || strings.Contains(line, "level=ERROR") ||
				strings.Contains(line, "outbox delivery error")) {
				if len(line) > 700 {
					line = line[:700]
				}
				t.Logf("captured log: %s", line)
				shown++
			}
		}
	})

	lab := &v3OAuthLab{tokens: map[string]time.Time{}, revoked: map[string]bool{}, revokeCalls: map[string]int{}}
	labSrv := httptest.NewServer(lab)
	t.Cleanup(labSrv.Close)
	secretRef := writeServedCredentialFile(t, "oauth-client", "lab-client-secret")
	provider := func(tenant, id string) config.DynamicSecretProviderConfig {
		return config.DynamicSecretProviderConfig{
			TenantID: tenant, ID: id, Type: "oauth-client-credentials",
			Endpoint: labSrv.URL + "/token", RevocationEndpoint: labSrv.URL + "/revoke",
			ClientID: "trstctl-leases", ClientSecretRef: secretRef, AllowedRoles: []string{"reader"},
			RoleBindings: map[string]string{"reader": "orders.read"}, MaxTTL: "5m", AllowInsecureLoopback: true,
		}
	}
	providers, err := dynamicSecretProvidersFromConfig(ctx,
		[]config.DynamicSecretProviderConfig{
			provider(servedTestTenant, "orders-api"), provider(servedTestTenant, "orders-api-rot"), provider(tenantB, "orders-api"),
		}, nil, serverTestPrincipalKEK(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// The production custody composition (run.go runTenantCustodyFromConfig):
	// one local wrapper registry shared by the tenant-crypto resolver and the
	// key-domain lifecycle, over a history-aware event log.
	admin := newServerTestStore(t)
	cutover := storetest.ProvisionRewrapCutover(t, admin, serverTestPostgresDSN(t))
	cr029AllowDisposablePeerLogin(t, admin, serverTestPostgresDSN(t), cutover.Cutover.NewLoginRole)
	st, err := store.Open(ctx, cutover.DSN, store.WithRewrapFleetCutover(cutover.Cutover))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.RequireRewrapFleetCutover(ctx, cutover.Cutover); err != nil {
		t.Fatalf("disposable fleet cutover: %v", err)
	}
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	wrapperPath := filepath.Join(t.TempDir(), "v3-custody.key")
	if err := os.WriteFile(wrapperPath, bytes.Repeat([]byte{0x3c}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{ID: "v3-custody", Path: wrapperPath}})
	if err != nil {
		t.Fatal(err)
	}
	eventOptions := []events.OpenOption{
		events.WithRequiredPrivacyEventPolicies(),
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(st)),
		events.WithHistoryRewriteContinuityVerifier(historycontinuity.NewReceiptVerifier(auditKey)),
	}
	h := newServedHarnessWithOwnedStore(t, config.Protocols{}, eventOptions, st, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = providers
		access, err := tenantseal.NewAccess(d.Store, d.KEK, registry)
		if err != nil {
			t.Fatal(err)
		}
		lifecycle, err := tenantseal.NewLifecycle(d.Store, d.Log, d.KEK, registry, historyRewriteProofOptions(d.Store, auditKey)...)
		if err != nil {
			t.Fatal(err)
		}
		protector, err := tenantseal.NewResultProtector(access)
		if err != nil {
			t.Fatal(err)
		}
		d.TenantCrypto = access
		d.TenantKeyDomains = lifecycle
		d.IdempotencyResultProtector = protector
	})
	registerServedTenant(t, h, "V3 LI-4-L3 tenant A")
	registerServedTenantID(t, h, tenantB, "V3 LI-4-L3 tenant B")
	tokA := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "keys:read", "keys:write")
	tokB := seedScopedToken(t, h.store, tenantB, "secrets:read", "secrets:write")

	startDispatcher := func() func() {
		runCtx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.srv.RunDispatcher(runCtx)
		}()
		var once sync.Once
		stop := func() { once.Do(func() { cancel(); <-done }) }
		t.Cleanup(stop)
		return stop
	}
	resourceClient := netsec.InsecureLoopbackClient(5 * time.Second)
	resource := func(token string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, labSrv.URL+"/orders", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := resourceClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	issue := func(tok, providerID, key string) (string, string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, key,
			map[string]any{"provider": providerID, "role": "reader", "ttl_seconds": 60})
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("issue %s: %d %s", key, status, body)
		}
		var lease dynamicLeaseView
		if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
			t.Fatalf("decode lease %s: %v %s", key, err, body)
		}
		var credential struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.AccessToken == "" {
			t.Fatalf("lease %s credential: %v", key, err)
		}
		return lease.ID, credential.AccessToken
	}
	readLease := func(tok, id string) dynamicLeaseView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+id, tok, nil)
		var lease dynamicLeaseView
		if status != http.StatusOK || json.Unmarshal(body, &lease) != nil {
			t.Fatalf("read lease %s: %d %s", id, status, body)
		}
		return lease
	}

	// 1. Both tenants are on the deployment KEK; each issues an OAuth lease.
	stop := startDispatcher()
	leaseA, tokenA := issue(tokA, "orders-api", "v3-li4-l3-lease-a")
	leaseB, tokenB := issue(tokB, "orders-api", "v3-li4-l3-lease-b")
	if resource(tokenA) != http.StatusOK || resource(tokenB) != http.StatusOK {
		t.Fatal("the resource server refused a freshly leased token")
	}
	stop()

	// 2. Both revoke while the provider revocation is still pending: the
	// worker has not delivered it yet (here it is stopped; in production a
	// provider outage or the outbox backoff leaves the same window open).
	for _, r := range []struct{ tok, id string }{{tokA, leaseA}, {tokB, leaseB}} {
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+r.id+"/revoke", r.tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
			t.Fatalf("revoke %s: %d %s", r.id, status, body)
		}
	}
	recordA, err := h.store.GetDynamicSecretLease(ctx, h.tenant, leaseA)
	if err != nil || recordA.State != store.DynamicSecretLeaseRevoked || recordA.RevocationStatus != store.DynamicSecretRevocationPending || len(recordA.RevocationSealedCredential) == 0 {
		t.Fatalf("tenant A lease before the migration: state=%s revocation=%s retained=%d err=%v",
			recordA.State, recordA.RevocationStatus, len(recordA.RevocationSealedCredential), err)
	}
	if label, err := seal.Domain(recordA.RevocationSealedCredential); err != nil || label != nil {
		t.Fatalf("tenant A's retained credential before the migration: label=%q err=%v (want a deployment-KEK container)", label, err)
	}

	// 3. Tenant A moves to its own key domain through the served route.
	migrate := servedTenantSealRequest(t, h.srv, tokA, http.MethodPost, "/api/v1/platform/tenant-key-domain/migrate",
		"v3-li4-l3-migrate", []byte(`{"wrapper_kind":"local_file","wrapper_id":"v3-custody"}`))
	if migrate.Code != http.StatusOK {
		state, stateErr := h.store.GetTenantKeyDomain(ctx, h.tenant)
		t.Fatalf("migrate tenant A = %d body=%s state=%s operation=%s last_error_code=%s last_error=%q state_err=%v",
			migrate.Code, migrate.Body.String(), state.State, state.OperationStatus, state.LastErrorCode, state.LastError, stateErr)
	}
	t.Logf("tenant A migrated: %s", strings.TrimSpace(migrate.Body.String()))
	recordA, err = h.store.GetDynamicSecretLease(ctx, h.tenant, leaseA)
	if err != nil {
		t.Fatal(err)
	}
	labelA, _ := seal.Domain(recordA.RevocationSealedCredential)
	t.Logf("after the migration tenant A's revocation_sealed_credential label=%q (empty = still the deployment-KEK container)", labelA)

	// 4. The worker runs. Tenant B (the control, not migrated) completes.
	stopAfterMigration := startDispatcher()
	deadline := time.Now().Add(45 * time.Second)
	for readLease(tokB, leaseB).RevocationStatus != "completed" {
		if time.Now().After(deadline) {
			t.Fatalf("control: tenant B's revocation did not complete: %+v", readLease(tokB, leaseB))
		}
		time.Sleep(200 * time.Millisecond)
	}
	revokedB, callsB := lab.state(tokenB)
	t.Logf("control tenant B: revocation completed; provider revoke calls=%d revoked=%t resource=%d", callsB, revokedB, resource(tokenB))
	if !revokedB || resource(tokenB) != http.StatusUnauthorized {
		t.Fatal("control: tenant B's token was not revoked at the authorization server")
	}

	// Tenant A: give the worker the same budget plus its first retries.
	for time.Now().Before(deadline) {
		if revoked, _ := lab.state(tokenA); revoked {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	revokedA, callsA := lab.state(tokenA)
	viewA := readLease(tokA, leaseA)
	var attempts int
	var lastError *string
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT attempts, last_error FROM outbox WHERE tenant_id = $1 AND destination = 'dynsecret.revoke' AND effect_lane = 'dynsecret.provider:orders-api' ORDER BY id DESC LIMIT 1`,
		h.tenant).Scan(&attempts, &lastError); err != nil {
		t.Logf("read tenant A outbox row: %v", err)
	}
	lastErrorText := ""
	if lastError != nil {
		lastErrorText = *lastError
	}
	var openFailures []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, leaseA) && strings.Contains(line, "outbox delivery error") {
			openFailures = append(openFailures, line)
		}
	}
	t.Logf("tenant A after the migration: lease state=%s revocation=%s; outbox attempts=%d last_error=%q; provider revoke calls=%d revoked=%t; resource server answers %d",
		viewA.State, viewA.RevocationStatus, attempts, lastErrorText, callsA, revokedA, resource(tokenA))
	for i, line := range openFailures {
		if i >= 3 {
			break
		}
		t.Logf("worker log: %s", line)
	}
	if !revokedA || resource(tokenA) != http.StatusUnauthorized {
		t.Errorf("LI-4-L3 (migrate): tenant A revoked its OAuth lease before migrating its key domain; after the migration the revocation worker made %d call(s) to the revocation endpoint (%d delivery attempt(s), %d logged open failure(s)) and the token is still accepted by the resource server (status %d), while the lease reads state=%s revocation=%s",
			callsA, attempts, len(openFailures), resource(tokenA), viewA.State, viewA.RevocationStatus)
	}

	// 5. The same window across a key-domain ROTATION. Tenant A, now on its own
	// domain (generation 1), issues a lease on a second provider lane, revokes
	// it while the worker is stopped, and rotates to generation 2.
	stopAfterMigration()
	stopIssue := startDispatcher()
	leaseR, tokenR := issue(tokA, "orders-api-rot", "v3-li4-l3-lease-rot")
	stopIssue()
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+leaseR+"/revoke", tokA, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke %s: %d %s", leaseR, status, body)
	}
	recordR, err := h.store.GetDynamicSecretLease(ctx, h.tenant, leaseR)
	if err != nil || len(recordR.RevocationSealedCredential) == 0 {
		t.Fatalf("tenant A rotation-lane lease before the rotation: retained=%d err=%v", len(recordR.RevocationSealedCredential), err)
	}
	labelBefore, _ := seal.Domain(recordR.RevocationSealedCredential)
	rotate := servedTenantSealRequest(t, h.srv, tokA, http.MethodPost, "/api/v1/platform/tenant-key-domain/rotate", "v3-li4-l3-rotate", nil)
	if rotate.Code != http.StatusOK {
		t.Fatalf("rotate tenant A = %d body=%s", rotate.Code, rotate.Body.String())
	}
	recordR, err = h.store.GetDynamicSecretLease(ctx, h.tenant, leaseR)
	if err != nil {
		t.Fatal(err)
	}
	labelAfter, _ := seal.Domain(recordR.RevocationSealedCredential)
	t.Logf("tenant A rotated to generation 2; the pending revocation's credential label before=%q after=%q", labelBefore, labelAfter)
	startDispatcher()
	rotDeadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(rotDeadline) {
		if revoked, _ := lab.state(tokenR); revoked {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	revokedR, callsR := lab.state(tokenR)
	viewR := readLease(tokA, leaseR)
	var rotFailures []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, leaseR) && strings.Contains(line, "outbox delivery error") {
			rotFailures = append(rotFailures, line)
		}
	}
	t.Logf("tenant A after the rotation: lease state=%s revocation=%s; provider revoke calls=%d revoked=%t; resource server answers %d; logged open failures=%d",
		viewR.State, viewR.RevocationStatus, callsR, revokedR, resource(tokenR), len(rotFailures))
	if len(rotFailures) > 0 {
		t.Logf("worker log: %s", rotFailures[0])
	}
	if !revokedR || resource(tokenR) != http.StatusUnauthorized {
		t.Errorf("LI-4-L3 (rotate): tenant A revoked an OAuth lease before rotating its key domain; after the rotation the revocation worker made %d call(s) to the revocation endpoint and the token is still accepted (status %d), lease state=%s revocation=%s",
			callsR, resource(tokenR), viewR.State, viewR.RevocationStatus)
	}
}

// The bundled test database normally admits only its postgres peer. This
// narrow, temporary peer mapping lets the disposable cutover's new login use
// the same private Unix socket, without opening TCP or changing other roles.
func cr029AllowDisposablePeerLogin(t *testing.T, admin *store.Store, dsn, role string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	socketDir := parsed.Query().Get("host")
	info, err := os.Stat(socketDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 ||
		!strings.HasPrefix(filepath.Base(socketDir), "trstctl-pg-socket-") ||
		!strings.HasPrefix(role, "r2_new_") || strings.Trim(role, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
		t.Fatal("CR-029 cutover must use the test-owned private socket and disposable login")
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	hbaPath := filepath.Join(socketDir, "pg_hba.conf")
	identPath := filepath.Join(socketDir, "pg_ident.conf")
	root, err := os.OpenRoot(socketDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	hba, err := root.ReadFile("pg_hba.conf")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := root.ReadFile("pg_ident.conf")
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, body []byte) error {
		f, err := os.CreateTemp(socketDir, ".cr029-peer-*")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(f.Name()) }()
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			return err
		}
		if _, err := f.Write(body); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return os.Rename(f.Name(), path)
	}
	reload := func() error {
		var ok bool
		if err := admin.SystemPool().QueryRow(context.Background(), `SELECT pg_reload_conf()`).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("PostgreSQL refused to reload the disposable peer mapping")
		}
		return nil
	}
	t.Cleanup(func() {
		if err := write(hbaPath, hba); err != nil {
			t.Errorf("restore test HBA: %v", err)
		}
		if err := write(identPath, ident); err != nil {
			t.Errorf("restore test peer map: %v", err)
		}
		if err := reload(); err != nil {
			t.Errorf("reload restored test peer map: %v", err)
		}
	})
	if err := write(hbaPath, append(append([]byte(nil), hba...), []byte("local all "+role+" peer map=trstctl_bundled\n")...)); err != nil {
		t.Fatal(err)
	}
	if err := write(identPath, append(append([]byte(nil), ident...), []byte("trstctl_bundled "+account.Username+" "+role+"\n")...)); err != nil {
		t.Fatal(err)
	}
	if err := reload(); err != nil {
		t.Fatal(err)
	}
}
