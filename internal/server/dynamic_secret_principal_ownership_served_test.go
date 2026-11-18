// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/dynsecret"
)

// CR-220: a dynamic-secret lease never receives another lease's database
// principal. Every lease's role name used to end in an unkeyed digest of its
// lease ID, and the lease ID derives from the caller's Idempotency-Key, so two
// leases could be made to share a name; the second issue then dropped the
// first lease's role (PostgreSQL also dropped what it owned) and re-created it
// for the second. Names now end in a suffix keyed under the deployment key and
// bound to the tenant, its registration epoch, the provider and the lease.

// serverTestPrincipalKEK is one process-wide deployment key for the tests that
// build dynamic-secret providers directly: like the served deployment KEK, it
// derives each lease's keyed principal suffix (CR-220). A provider without a
// key that can derive it refuses every lease, so these tests pass one.
var serverTestPrincipalKEK = sync.OnceValue(func() *seal.LocalKEK {
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		panic(err)
	}
	return kek
})

// serverTestPrincipalSuffix stands in for the control plane's keyed suffix in
// the tests that call a backend directly, past the provider that derives it.
func serverTestPrincipalSuffix(leaseID string) string {
	return crypto.SHA256Hex([]byte("test principal suffix\x00" + leaseID))[:16]
}

// principalOwnershipTenantB is the second tenant sharing one database server.
const principalOwnershipTenantB = "22222222-2222-2222-2222-222222222222"

// principalOwnershipPairs are pairs of Idempotency-Keys whose leases got ONE
// role name under the earlier, unkeyed derivation. Each pair is checked below,
// so a change to the lease-ID derivation or the tenants fails loudly instead of
// quietly testing nothing.
var principalOwnershipPairs = []struct {
	name                      string
	tenantA, keyA, tenB, keyB string
}{
	{"two tenants on one server", servedTestTenant, "tenant-a-issue-744355", principalOwnershipTenantB, "tenant-b-issue-791538"},
	{"two callers in one tenant", servedTestTenant, "tenant-a-issue-1288001", servedTestTenant, "tenant-a-second-2250791"},
}

// unkeyedLeaseNameSuffix is the suffix earlier releases named a lease's role
// with: the first ten hex digits of SHA-256 over the served lease ID.
func unkeyedLeaseNameSuffix(tenantID, idempotencyKey string) string {
	lease := "lease-" + uuid.NewSHA1(dynamicSecretLeaseNamespace, []byte(tenantID+"\x00"+idempotencyKey)).String()
	return crypto.SHA256Hex([]byte(lease))[:10]
}

func TestServedLeasesSharingADatabaseNeverShareARole(t *testing.T) {
	ctx := context.Background()
	dsn := serverTestPostgresDSN(t)
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminRef := writeServedCredentialFile(t, "cr220-admin-dsn", dsn)
	// Both tenants use the same provider ID and prefix on the same server, as
	// two tenants left on the shared defaults would.
	providerFor := func(tenantID string) config.DynamicSecretProviderConfig {
		return config.DynamicSecretProviderConfig{
			TenantID: tenantID, ID: "shared-pg", Type: "postgresql",
			AdminDSNRef: adminRef, Database: parsed.Database, Schema: "public",
			UsernamePrefix: "cr220", AllowedRoles: []string{"readonly"}, MaxTTL: time.Hour.String(),
		}
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		resolver := integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{
			servedTestTenant:          {newConfiguredDynamicProvider(providerFor(servedTestTenant), map[string]bool{"readonly": true}, time.Hour, resolver, nil)},
			principalOwnershipTenantB: {newConfiguredDynamicProvider(providerFor(principalOwnershipTenantB), map[string]bool{"readonly": true}, time.Hour, resolver, nil)},
		}
	})
	registerServedTenantID(t, h, servedTestTenant, "CR-220 tenant A")
	registerServedTenantID(t, h, principalOwnershipTenantB, "CR-220 tenant B")
	startServedExternalCADispatcher(t, h)
	tokens := map[string]string{
		servedTestTenant:          seedScopedTokenSubject(t, h.store, servedTestTenant, "cr220-caller-a", "secrets:read", "secrets:write"),
		principalOwnershipTenantB: seedScopedTokenSubject(t, h.store, principalOwnershipTenantB, "cr220-caller-b", "secrets:read", "secrets:write"),
	}
	issue := func(t *testing.T, tenantID, key string) dynamicLeaseView {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tokens[tenantID], key,
			map[string]any{"provider": "shared-pg", "role": "readonly", "ttl_seconds": 600})
		if status != http.StatusCreated {
			t.Fatalf("issue a lease with key %s in tenant %s: %d %s", key, tenantID, status, body)
		}
		var lease dynamicLeaseView
		if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
			t.Fatalf("decode the lease: %v %s", err, body)
		}
		return lease
	}
	login := func(t *testing.T, lease dynamicLeaseView) string {
		t.Helper()
		u, err := url.Parse(lease.Credential)
		if err != nil || u.User == nil {
			t.Fatalf("the lease credential is not a DSN with a login")
		}
		return u.User.Username()
	}
	connects := func(lease dynamicLeaseView) error {
		conn, err := pgx.Connect(ctx, lease.Credential)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close(context.Background()) }()
		var one int
		return conn.QueryRow(ctx, "SELECT 1").Scan(&one)
	}

	for _, pair := range principalOwnershipPairs {
		t.Run(pair.name, func(t *testing.T) {
			if unkeyedLeaseNameSuffix(pair.tenantA, pair.keyA) != unkeyedLeaseNameSuffix(pair.tenB, pair.keyB) {
				t.Fatal("fixture: the two leases no longer shared one unkeyed name suffix; recompute the pair")
			}
			first := issue(t, pair.tenantA, pair.keyA)
			if err := connects(first); err != nil {
				t.Fatalf("the first lease's credential does not log in: %v", err)
			}
			second := issue(t, pair.tenB, pair.keyB)
			if a, b := login(t, first), login(t, second); a == b {
				t.Errorf("two leases (tenant %s key %s, tenant %s key %s) were issued one database role %q", pair.tenantA, pair.keyA, pair.tenB, pair.keyB, a)
			}
			if err := connects(first); err != nil {
				t.Errorf("the second lease's issue took the first lease's role away: its credential no longer logs in: %v", err)
			}
			if err := connects(second); err != nil {
				t.Errorf("the second lease's credential does not log in: %v", err)
			}
			for _, lease := range []struct {
				tenantID string
				view     dynamicLeaseView
			}{{pair.tenantA, first}, {pair.tenB, second}} {
				if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.view.ID+"/revoke", tokens[lease.tenantID], "revoke-"+lease.view.ID, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
					t.Errorf("revoke lease %s: %d %s", lease.view.ID, status, body)
				}
			}
		})
	}
}

// errNoRows reports a pgx no-rows result.
func errNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// postgresRoleExists reports whether a role named name exists on the server.
func postgresRoleExists(t *testing.T, ctx context.Context, admin *pgx.Conn, name string) bool {
	t.Helper()
	var found string
	err := admin.QueryRow(ctx, "SELECT rolname FROM pg_roles WHERE rolname = $1", name).Scan(&found)
	if errNoRows(err) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.EqualFold(found, name)
}

// CR-220: a crash retry of one lease (its issued result lost after the first
// attempt, so the worker generates again for the same lease and epoch)
// converges on that lease's own role: one role, the first attempt's password
// refused, the retry's accepted, and revocation drops the role.
func TestServedLeaseRetryConvergesOnItsOwnRole(t *testing.T) {
	ctx := context.Background()
	dsn := serverTestPostgresDSN(t)
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DynamicSecretProviderConfig{
		TenantID: servedTestTenant, ID: "retry-pg", Type: "postgresql",
		AdminDSNRef: writeServedCredentialFile(t, "cr220-retry-admin-dsn", dsn), Database: parsed.Database, Schema: "public",
		UsernamePrefix: "cr220r", AllowedRoles: []string{"readonly"}, MaxTTL: time.Hour.String(),
	}
	provider := newConfiguredDynamicProvider(cfg, map[string]bool{"readonly": true}, time.Hour,
		integrationCredentialResolver{kek: serverTestPrincipalKEK()}, nil)
	req := dynsecret.GenerateRequest{Role: "readonly", TTL: 10 * time.Minute, LeaseID: "lease-cr220-retry", TenantEpoch: "cr220-epoch-1"}
	first, err := provider.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := provider.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if first.BackendRef != retry.BackendRef {
		t.Fatalf("a retry of one lease named %q, the first attempt %q", retry.BackendRef, first.BackendRef)
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	var roles int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname LIKE 'cr220r\_%'`).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if roles != 1 {
		t.Fatalf("the lease and its retry left %d roles, want 1", roles)
	}
	if conn, err := pgx.Connect(ctx, string(first.Secret)); err == nil {
		_ = conn.Close(context.Background())
		t.Fatal("the first attempt's password still logs in after the retry replaced it")
	}
	conn, err := pgx.Connect(ctx, string(retry.Secret))
	if err != nil {
		t.Fatalf("the retry's credential does not log in: %v", err)
	}
	_ = conn.Close(context.Background())
	if err := provider.Revoke(ctx, retry.BackendRef); err != nil {
		t.Fatal(err)
	}
	if postgresRoleExists(t, ctx, admin, retry.BackendRef) {
		t.Fatalf("revocation left the lease's role %q", retry.BackendRef)
	}
}

// legacyNamedProvider issues the way earlier releases did: the lease's role
// ends in the unkeyed ten-digit digest of its lease ID. Revocation is the
// current provider's own.
type legacyNamedProvider struct {
	*configuredDynamicProvider
	adminDSN string
}

func (p legacyNamedProvider) Generate(ctx context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	name, err := dynsecret.LegacyLeasePrincipalName(p.cfg.UsernamePrefix, req.Role, req.LeaseID, 63, "_")
	if err != nil {
		return dynsecret.Credential{}, err
	}
	conn, err := pgx.Connect(ctx, p.adminDSN)
	if err != nil {
		return dynsecret.Credential{}, err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, "CREATE ROLE "+pgx.Identifier{name}.Sanitize()+" LOGIN"); err != nil {
		return dynsecret.Credential{}, err
	}
	return dynsecret.Credential{BackendRef: name, Secret: []byte("postgres://" + name + "@legacy.invalid/app")}, nil
}

// CR-220 upgrade: a lease an earlier release issued keeps its recorded
// ten-digit role name, and the current build still revokes it, through the
// API and through expiry.
func TestServedLeasesFromAnEarlierReleaseStillRevoke(t *testing.T) {
	ctx := context.Background()
	dsn := serverTestPostgresDSN(t)
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DynamicSecretProviderConfig{
		TenantID: servedTestTenant, ID: "legacy-pg", Type: "postgresql",
		AdminDSNRef: writeServedCredentialFile(t, "cr220-legacy-admin-dsn", dsn), Database: parsed.Database, Schema: "public",
		UsernamePrefix: "cr220l", AllowedRoles: []string{"readonly"}, MaxTTL: time.Hour.String(),
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		resolver := integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}
		current := newConfiguredDynamicProvider(cfg, map[string]bool{"readonly": true}, time.Hour, resolver, nil).(*configuredDynamicProvider)
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {legacyNamedProvider{configuredDynamicProvider: current, adminDSN: dsn}}}
		d.DynamicLeaseWorkerInterval = 10 * time.Millisecond
	})
	registerServedTenantID(t, h, servedTestTenant, "CR-220 upgrade tenant")
	startServedExternalCADispatcher(t, h)
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
	token := seedScopedTokenSubject(t, h.store, servedTestTenant, "cr220-upgrade-caller", "secrets:read", "secrets:write")
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	issueLegacy := func(t *testing.T, key string, ttlSeconds int) (dynamicLeaseView, string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", token, key,
			map[string]any{"provider": "legacy-pg", "role": "readonly", "ttl_seconds": ttlSeconds})
		if status != http.StatusCreated {
			t.Fatalf("issue: %d %s", status, body)
		}
		var lease dynamicLeaseView
		if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" {
			t.Fatalf("decode the lease: %v %s", err, body)
		}
		name, err := dynsecret.LegacyLeasePrincipalName("cr220l", "readonly", lease.ID, 63, "_")
		if err != nil {
			t.Fatal(err)
		}
		if !postgresRoleExists(t, ctx, admin, name) {
			t.Fatalf("the earlier release's role %q was not created", name)
		}
		return lease, name
	}
	waitDropped := func(t *testing.T, name string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for postgresRoleExists(t, ctx, admin, name) {
			if time.Now().After(deadline) {
				t.Fatalf("the earlier release's role %q was never dropped", name)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}

	t.Run("revoked through the API", func(t *testing.T) {
		lease, name := issueLegacy(t, "cr220-upgrade-revoke", 600)
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", token, "cr220-upgrade-revoke-call", map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
			t.Fatalf("revoke: %d %s", status, body)
		}
		waitDropped(t, name)
	})
	t.Run("revoked at expiry", func(t *testing.T) {
		_, name := issueLegacy(t, "cr220-upgrade-expire", 1)
		waitDropped(t, name)
	})
}
