// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
)

type dynamicLeaseView struct {
	ID               string    `json:"id"`
	Provider         string    `json:"provider"`
	Role             string    `json:"role"`
	State            string    `json:"state"`
	Credential       string    `json:"credential"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	RevocationStatus string    `json:"revocation_status"`
}

type dynamicLeaseRotationView struct {
	ID           string     `json:"id"`
	Phase        string     `json:"phase"`
	Terminal     bool       `json:"terminal"`
	OldRef       string     `json:"old_ref"`
	NewRef       string     `json:"new_ref"`
	VerifyMode   string     `json:"verify_mode"`
	Error        string     `json:"error"`
	TTLSeconds   int        `json:"ttl_seconds"`
	NewExpiresAt *time.Time `json:"new_expires_at"`
}

// dynamicLeaseRotationOutcome is what one rotation journey leaves behind.
type dynamicLeaseRotationOutcome struct {
	old, new           dynamicLeaseView
	command            dynamicLeaseRotationView
	oldCredential      string
	published          string
	publishedVersion   int
	predecessorVersion int
}

func writeServedCredentialFile(t *testing.T, name, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil { // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
		t.Fatal(err)
	}
	return "file:" + path
}

// runDynamicLeaseRotationJourney issues lease L1 (initialTTL) and publishes its
// credential as the secret named role, then rotates it through
// POST /api/v1/secrets/rotations with ttl_seconds = rotatedTTL and follows the
// command to its terminal phase. Every read goes through the served API.
func runDynamicLeaseRotationJourney(t *testing.T, h *servedHarness, tok, providerID, role string, initialTTL, rotatedTTL int) dynamicLeaseRotationOutcome {
	t.Helper()
	readLease := func(id string) dynamicLeaseView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+id, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read lease %s: %d %s", id, status, body)
		}
		var lease dynamicLeaseView
		if err := json.Unmarshal(body, &lease); err != nil {
			t.Fatal(err)
		}
		return lease
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a201-"+providerID+"-l1",
		map[string]any{"provider": providerID, "role": role, "ttl_seconds": initialTTL})
	if status != http.StatusCreated {
		t.Fatalf("issue the first lease: %d %s", status, body)
	}
	var old dynamicLeaseView
	if err := json.Unmarshal(body, &old); err != nil || old.ID == "" || old.Credential == "" {
		t.Fatalf("decode the first lease: %v %s", err, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "a201-"+providerID+"-seed",
		map[string]any{"name": role, "value": old.Credential}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("publish the first lease: %d %s", status, body)
	}
	readSecret := func() (string, int) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+role, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read secret: %d %s", status, body)
		}
		var out struct {
			Value   string `json:"value"`
			Version int    `json:"version"`
		}
		_ = json.Unmarshal(body, &out)
		return out.Value, out.Version
	}
	_, predecessorVersion := readSecret()

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "a201-"+providerID+"-rotate",
		map[string]any{"provider": "dynamic-lease:" + providerID, "key": role, "old_ref": old.ID, "ttl_seconds": rotatedTTL})
	if status != http.StatusOK {
		t.Fatalf("queue the dynamic-lease rotation: %d %s", status, body)
	}
	var queued struct {
		Queued    bool   `json:"queued"`
		CommandID string `json:"command_id"`
	}
	if err := json.Unmarshal(body, &queued); err != nil || !queued.Queued || queued.CommandID == "" {
		t.Fatalf("queued evidence: %v %s", err, body)
	}
	var command dynamicLeaseRotationView
	deadline := time.Now().Add(90 * time.Second)
	for {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+queued.CommandID, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read the command: %d %s", status, body)
		}
		command = dynamicLeaseRotationView{}
		_ = json.Unmarshal(body, &command)
		if command.Terminal {
			break
		}
		if time.Now().After(deadline) {
			var lastError string
			_ = h.store.SystemPool().QueryRow(context.Background(),
				`SELECT coalesce(last_error, '') FROM outbox WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1`, h.tenant).Scan(&lastError)
			t.Fatalf("the command did not finish: %+v (last outbox error %q)", command, lastError)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if command.Phase != "completed" || command.NewRef == "" || command.NewRef == old.ID || command.TTLSeconds != rotatedTTL || command.NewExpiresAt == nil {
		t.Fatalf("the command = %+v, want completed with a new lease of ttl %d", command, rotatedTTL)
	}
	published, publishedVersion := readSecret()
	return dynamicLeaseRotationOutcome{
		old: readLease(old.ID), new: readLease(command.NewRef), command: command, oldCredential: old.Credential,
		published: published, publishedVersion: publishedVersion, predecessorVersion: predecessorVersion,
	}
}

// checkDynamicLeaseRotationOutcome asserts what every provider's journey must
// show through the API: the new lease lives exactly the requested TTL, the
// secret's next version is its credential, and the old lease is revoked with
// the provider's removal completed.
func checkDynamicLeaseRotationOutcome(t *testing.T, out dynamicLeaseRotationOutcome, rotatedTTL int, verifyMode string) {
	t.Helper()
	if lifetime := out.new.ExpiresAt.Sub(out.new.IssuedAt); lifetime < time.Duration(rotatedTTL-2)*time.Second || lifetime > time.Duration(rotatedTTL+2)*time.Second {
		t.Fatalf("the new lease lives %s, want %ds", lifetime, rotatedTTL)
	}
	if out.command.NewExpiresAt.Sub(out.new.ExpiresAt).Abs() > time.Second {
		t.Fatalf("command new_expires_at %s, lease expires_at %s", out.command.NewExpiresAt, out.new.ExpiresAt)
	}
	if out.new.State != "active" {
		t.Fatalf("the new lease is %q", out.new.State)
	}
	if out.publishedVersion != out.predecessorVersion+1 || out.published == "" || out.published == out.oldCredential {
		t.Fatalf("the secret is version %d (from %d), want the new lease's credential as the next version", out.publishedVersion, out.predecessorVersion)
	}
	if out.command.VerifyMode != verifyMode {
		t.Fatalf("verify_mode = %q, want %q", out.command.VerifyMode, verifyMode)
	}
	if out.old.State != "revoked" || out.old.RevocationStatus != "completed" {
		t.Fatalf("the old lease is %q with revocation %q, want revoked and completed", out.old.State, out.old.RevocationStatus)
	}
}

// TestServedDynamicLeaseRotationIssuesTheRequestedTTLAndRetiresTheOldLease is
// A201 against the server tests' own PostgreSQL, through a provider configured
// as the binary configures one. Read back without trstctl, the published
// credential logs in as the new lease's role, and the old lease's role is gone
// from pg_roles and can no longer log in.
func TestServedDynamicLeaseRotationIssuesTheRequestedTTLAndRetiresTheOldLease(t *testing.T) {
	ctx := context.Background()
	dsn := serverTestPostgresDSN(t)
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "pg-leases", Type: "postgresql",
		AdminDSNRef: writeServedCredentialFile(t, "pg-admin-dsn", dsn), Database: parsed.Database,
		AllowedRoles: []string{"reporting"}, MaxTTL: "1h", UsernamePrefix: "trstctl_a201",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "dynamic-lease rotation tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	// Refusals before any effect: ttl_seconds is required, bounded by the
	// provider's maximum, and the provider must exist.
	for _, c := range []struct {
		body map[string]any
		want int
	}{
		{map[string]any{"provider": "dynamic-lease:pg-leases", "key": "reporting", "old_ref": "none"}, http.StatusBadRequest},
		{map[string]any{"provider": "dynamic-lease:pg-leases", "key": "reporting", "old_ref": "none", "ttl_seconds": 7200}, http.StatusUnprocessableEntity},
		{map[string]any{"provider": "dynamic-lease:absent", "key": "reporting", "old_ref": "none", "ttl_seconds": 600}, http.StatusServiceUnavailable},
	} {
		key := "a201-refusal-" + c.body["provider"].(string) + "-" + time.Now().Format("150405.000000000")
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, key, c.body); status != c.want {
			t.Fatalf("rotation %v = %d %s, want %d", c.body, status, body, c.want)
		}
	}

	out := runDynamicLeaseRotationJourney(t, h, tok, "pg-leases", "reporting", 600, 1800)
	checkDynamicLeaseRotationOutcome(t, out, 1800, "connected")

	// Without trstctl: the published credential logs in as its own role; the
	// old lease's role is gone.
	conn, err := pgx.Connect(ctx, out.published)
	if err != nil {
		t.Fatalf("the published credential does not log in: %v", err)
	}
	var newUser string
	if err := conn.QueryRow(ctx, `SELECT current_user`).Scan(&newUser); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
	oldConfig, err := pgx.ParseConfig(out.oldCredential)
	if err != nil {
		t.Fatal(err)
	}
	if newUser == oldConfig.User {
		t.Fatalf("the published credential is the old lease's role %q", newUser)
	}
	var roles int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname = $1`, oldConfig.User).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if roles != 0 {
		t.Fatalf("the old lease's role %q still exists", oldConfig.User)
	}
	if old, err := pgx.Connect(ctx, out.oldCredential); err == nil {
		_ = old.Close(ctx)
		t.Fatal("the old lease's credential still logs in")
	}

	// The same old_ref, now revoked, cannot be rotated again.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "a201-stale-old-ref",
		map[string]any{"provider": "dynamic-lease:pg-leases", "key": "reporting", "old_ref": out.old.ID, "ttl_seconds": 600}); status != http.StatusConflict {
		t.Fatalf("rotating a revoked lease = %d %s, want 409", status, body)
	}
	t.Logf("A201_POSTGRES_OK new=%s old=%s ttl=%ds", out.new.ID, out.old.ID, out.command.TTLSeconds)
}

// leaseRotationDouble is a postgresql-typed lease provider whose credential
// check can be made to fail.
type leaseRotationDouble struct {
	mu         sync.Mutex
	verifyFail bool
	verified   int
	revoked    []string
}

func (p *leaseRotationDouble) Name() string                               { return "pg-double" }
func (p *leaseRotationDouble) MaximumTTL() time.Duration                  { return time.Hour }
func (p *leaseRotationDouble) DynamicSecretProviderType() string          { return "postgresql" }
func (p *leaseRotationDouble) DynamicSecretAllowedRoles() []string        { return []string{"reporting"} }
func (p *leaseRotationDouble) DynamicSecretConfigurationRevision() string { return "rev-a201" }

func (p *leaseRotationDouble) Generate(_ context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return dynsecret.Credential{BackendRef: "role-" + req.LeaseID, Secret: []byte("dsn-for-" + req.LeaseID)}, nil
}

func (p *leaseRotationDouble) Revoke(_ context.Context, ref string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked = append(p.revoked, ref)
	return nil
}

func (p *leaseRotationDouble) VerifyLeaseCredential(context.Context, []byte) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verified++
	if p.verifyFail {
		return "connected", errors.New("double: the new lease's credential was refused")
	}
	return "connected", nil
}

// A201: a new lease whose credential still fails its check on the last
// attempt is rolled back like a static successor: the predecessor's value is
// published again as the next version, the new lease is revoked, and the old
// lease stays active.
func TestServedDynamicLeaseRotationRollsBackAnUnverifiedLease(t *testing.T) {
	provider := &leaseRotationDouble{verifyFail: true}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
	})
	registerServedTenant(t, h, "dynamic-lease rollback tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a201-rollback-l1",
		map[string]any{"provider": "pg-double", "role": "reporting", "ttl_seconds": 600})
	if status != http.StatusCreated {
		t.Fatalf("issue the first lease: %d %s", status, body)
	}
	var old dynamicLeaseView
	_ = json.Unmarshal(body, &old)
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "a201-rollback-seed",
		map[string]any{"name": "reporting", "value": old.Credential}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("publish the first lease: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "a201-rollback-rotate",
		map[string]any{"provider": "dynamic-lease:pg-double", "key": "reporting", "old_ref": old.ID, "ttl_seconds": 900})
	if status != http.StatusOK {
		t.Fatalf("queue the rotation: %d %s", status, body)
	}
	var queued struct {
		CommandID string `json:"command_id"`
	}
	_ = json.Unmarshal(body, &queued)
	var command dynamicLeaseRotationView
	deadline := time.Now().Add(90 * time.Second)
	for {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+queued.CommandID, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read the command: %d %s", status, body)
		}
		command = dynamicLeaseRotationView{}
		_ = json.Unmarshal(body, &command)
		if command.Terminal || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if command.Phase != "rolled_back" || command.NewRef == "" {
		t.Fatalf("the command = %+v, want rolled_back", command)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/reporting", tok, nil)
	var current struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	_ = json.Unmarshal(body, &current)
	if status != http.StatusOK || current.Value != old.Credential || current.Version != 3 {
		t.Fatalf("the secret after rollback = %d version %d, want the first lease's credential as version 3", status, current.Version)
	}
	lease := func(id string) dynamicLeaseView {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+id, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read lease %s: %d %s", id, status, body)
		}
		var view dynamicLeaseView
		_ = json.Unmarshal(body, &view)
		return view
	}
	if got := lease(command.NewRef); got.State != "revoked" {
		t.Fatalf("the unverified lease is %q, want revoked", got.State)
	}
	if got := lease(old.ID); got.State != "active" {
		t.Fatalf("the first lease is %q, want active", got.State)
	}
	provider.mu.Lock()
	verified := provider.verified
	provider.mu.Unlock()
	if verified < 3 {
		t.Fatalf("the credential was checked %d times before the rollback, want 3", verified)
	}
}
