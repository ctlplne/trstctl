// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
)

// TestBootstrapTokenAuthenticatesServedRequest is the WIRE-002 acceptance test:
// on a fresh boot the binary fails closed (every guarded route 401s) and there is
// no served way to obtain a credential, so the first-run `token create` bootstrap
// is the on-ramp. This proves it end to end against the embedded stack (bundled
// PostgreSQL + in-process NATS):
//
//  1. Fail-closed BEFORE bootstrap: GET /api/v1/owners with no credential -> 401,
//     and with a forged trst_ bearer -> 401 (the keystone posture, RED-004/WIRE PROTECT).
//  2. RunTokenCreate mints the first tenant-scoped token (the missing path).
//  3. The printed token authenticates the SAME served route -> 200.
//  4. The token is tenant-scoped: it lists only its own tenant's owners, never
//     another tenant's (AN-1 RLS).
//
// It exercises the production served path: api.New's default authenticated
// resolver (bearer token / OIDC), reached through server.Build's Handler() — the
// exact composition cmd/trstctl serves. It must FAIL on the pre-fix tree (no
// RunTokenCreate / no token-mint path exists) and PASS after, and is race-clean.
//
// Production runs the bootstrap as a SEPARATE `trstctl token create` process, so
// the embedded NATS path requires exclusive local custody. This test gives
// each phase its own short-lived event log (the bundled NATS runs in-process, so
// only one may be open at a time); tenant state survives across them because it is
// projected into PostgreSQL, the shared read model.
func TestBootstrapTokenAuthenticatesServedRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()

	// One embedded datastore for the whole test; the served handler and the
	// bootstrap (in external mode) both talk to it, so they share state.
	dsn := serverTestPostgresDSN(t)

	// A long-lived store the test owns for direct seeding/migration. It is NEVER
	// handed to Build, because server.Shutdown closes the store it is given — so each
	// served phase below gets its own throwaway store instead.
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	resetServerTestStore(t, st)

	// withServed builds the production control-plane handler (server.Build -> the
	// default authenticated resolver), runs fn against a live httptest server, then
	// tears it down — including its in-process event log and its own store — so only
	// one bundled NATS is ever open at a time (mirroring the bootstrap running as its
	// own process) and Shutdown's store.Close never touches the test's shared store.
	withServed := func(fn func(get func(bearer string) (int, []byte))) {
		phaseStore, err := store.Open(ctx, dsn)
		if err != nil {
			t.Fatalf("open served store: %v", err)
		}
		log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
		if err != nil {
			phaseStore.Close()
			t.Fatalf("open served event log: %v", err)
		}
		srv, err := Build(ctx, Deps{Store: phaseStore, Log: log})
		if err != nil {
			_ = log.Close()
			phaseStore.Close()
			t.Fatalf("build control plane: %v", err)
		}
		// srv.Shutdown closes both phaseStore and log; no extra Close here.
		defer func() { _ = srv.Shutdown(context.Background()) }()
		ts := httptest.NewServer(srv.Handler())
		defer ts.Close()

		get := func(bearer string) (int, []byte) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/owners", nil)
			if err != nil {
				t.Fatal(err)
			}
			if bearer != "" {
				req.Header.Set("Authorization", "Bearer "+bearer)
			}
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatalf("GET /api/v1/owners: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, body
		}
		fn(get)
	}

	const tenantA = "11111111-1111-1111-1111-111111111111"
	const tenantB = "22222222-2222-2222-2222-222222222222"

	// (1) Fail closed before any token exists — the pre-fix reality and the strength
	// WIRE-002 must not regress: no credential and a forged bearer both 401.
	withServed(func(get func(string) (int, []byte)) {
		if code, _ := get(""); code != http.StatusUnauthorized {
			t.Fatalf("fresh binary GET /api/v1/owners without auth = %d, want 401 (must fail closed)", code)
		}
		if code, _ := get("trst_forged_does_not_exist"); code != http.StatusUnauthorized {
			t.Fatalf("forged bearer GET /api/v1/owners = %d, want 401 (no token can exist pre-bootstrap)", code)
		}
	})

	// (2) Mint the first token via the network-trust-free bootstrap. It points at the
	// already-running database in external mode so it shares the served state, and
	// opens/closes its own event log internally (no NATS overlaps the served one).
	bootCfg := config.Default()
	bootCfg.Postgres = config.Postgres{Mode: config.PostgresExternal, DSN: dsn}
	bootNATSDir := t.TempDir()
	bootCfg.NATS = config.NATS{Mode: config.NATSEmbedded, StoreDir: bootNATSDir}
	bootCfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	bootCfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "credential-kek.bin")
	configureExternalAuditTestSigner(t, bootCfg)

	raw, err := RunTokenCreate(ctx, bootCfg, TokenCreateOptions{TenantID: tenantA, TenantName: "Acme", Subject: "ci-bot"})
	if err != nil {
		t.Fatalf("RunTokenCreate: %v", err)
	}
	if !bytes.HasPrefix(raw, []byte("trst_")) {
		t.Fatalf("bootstrap token %q does not carry the trst_ prefix", raw)
	}
	bearer := secrettext.String(raw)
	secret.Wipe(raw)
	registered, err := st.GetTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("load freshly registered tenant: %v", err)
	}

	// The generic AN-5 receipt is retained for seven days, while a local operator
	// may need to recover API access months later. Reproduce that real expiry by
	// deleting only the completed bootstrap receipt. The second local command must
	// verify the existing tenant's retained registration event, mint a fresh raw
	// token, and leave the registration sequence unchanged.
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
		tenantA, "bootstrap-tenant:"+tenantA); err != nil {
		t.Fatalf("expire bootstrap registration receipt: %v", err)
	}
	recoveredRaw, err := RunTokenCreate(ctx, bootCfg, TokenCreateOptions{
		TenantID: tenantA, TenantName: "ignored-existing-label", Subject: "recovery-bot",
	})
	if err != nil {
		t.Fatalf("RunTokenCreate after registration receipt expiry: %v", err)
	}
	if !bytes.HasPrefix(recoveredRaw, []byte("trst_")) || bytes.Equal(recoveredRaw, []byte(bearer)) {
		t.Fatal("existing-tenant recovery did not mint a distinct trst_ token")
	}
	recoveredBearer := secrettext.String(recoveredRaw)
	secret.Wipe(recoveredRaw)
	afterRecovery, err := st.GetTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("load tenant after bootstrap recovery: %v", err)
	}
	if afterRecovery.EventSeq != registered.EventSeq || afterRecovery.Name != registered.Name {
		t.Fatalf("bootstrap recovery changed tenant registration from %+v to %+v", registered, afterRecovery)
	}

	assertBootstrapTokensRecorded(t, ctx, st, bootCfg, tenantA, []string{bearer, recoveredBearer})

	// A SQL-only tenant row is not recovery authority. The command must refuse it
	// because no exact retained registration event backs the read model.
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantB, Name: "forged-sql-only"}); err != nil {
		t.Fatalf("seed SQL-only tenant row: %v", err)
	}
	forgedRaw, err := RunTokenCreate(ctx, bootCfg, TokenCreateOptions{
		TenantID: tenantB, TenantName: "forged-sql-only", Subject: "must-not-mint",
	})
	secret.Wipe(forgedRaw)
	if err == nil {
		t.Fatal("bootstrap recovery minted a token for a tenant row with no retained registration event")
	}

	// RED-004 guard: the bootstrap token must NOT carry issuance authority. The
	// default scope set withholds certs:issue (it only creates an API credential),
	// but it must be able to read the capability catalog so a clean client can
	// discover what this exact server can safely do.
	hasCapabilitiesRead := false
	for _, s := range BootstrapAdminScopes() {
		if s == "certs:issue" {
			t.Fatal("bootstrap default scopes include certs:issue; the first token must not open self-issue (RED-004)")
		}
		if s == string(authz.CapabilitiesRead) {
			hasCapabilitiesRead = true
		}
	}
	if !hasCapabilitiesRead {
		t.Fatal("bootstrap default scopes omit capabilities:read; a clean client cannot discover the server's supported operations")
	}

	// Plant an owner in the token's tenant (A) and one in another tenant (B) so the
	// scoping assertion has something to discriminate (AN-1 RLS).
	if _, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerWorkload, Name: "payments-A"}); err != nil {
		t.Fatalf("seed owner in tenant A: %v", err)
	}
	if _, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantB, Kind: store.OwnerWorkload, Name: "payments-B"}); err != nil {
		t.Fatalf("seed owner in tenant B: %v", err)
	}

	// (3+4) The printed token authenticates the SAME served route -> 200, and is
	// tenant-scoped: it lists ONLY its own tenant's owner.
	withServed(func(get func(string) (int, []byte)) {
		code, body := get(recoveredBearer)
		if code != http.StatusOK {
			t.Fatalf("bootstrap token GET /api/v1/owners = %d, want 200; body=%s", code, body)
		}
		var got struct {
			Items []struct {
				TenantID string `json:"tenant_id"`
				Name     string `json:"name"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode owner list: %v; body=%s", err, body)
		}
		if len(got.Items) != 1 {
			t.Fatalf("token listed %d owners, want exactly 1 (its own tenant); items=%+v", len(got.Items), got.Items)
		}
		if got.Items[0].TenantID != tenantA {
			t.Errorf("token listed an owner from tenant %q, want only its own tenant %q (RLS leak)", got.Items[0].TenantID, tenantA)
		}
		if got.Items[0].Name != "payments-A" {
			t.Errorf("token listed owner %q, want payments-A (its own tenant's)", got.Items[0].Name)
		}
	})
}

// The bootstrap command must use the same immutable token-created event as the
// served API. A credential that exists only in SQL disappears from audit and a
// read-model rebuild. Check both first registration and existing-tenant recovery.
func assertBootstrapTokensRecorded(t *testing.T, ctx context.Context, st *store.Store, cfg *config.Config, tenantID string, bearers []string) {
	t.Helper()
	signerRuntime, auditKey, err := openAuditSigningRuntime(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer signerRuntime.Close()
	log, err := openSanitizedHistoryAwareEventLog(ctx, cfg.NATS, st, auditKey, cfg.Secrets.SecretRotationHistoryFleetReady)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	expected := make(map[string]bool)
	for _, bearer := range bearers {
		raw := []byte(bearer)
		hash, err := auth.HashAPIToken(raw)
		secret.Wipe(raw)
		if err != nil {
			t.Fatal(err)
		}
		expected[hash] = false
	}
	count := 0
	err = log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID || ev.Type != projections.EventAPITokenCreated {
			return nil
		}
		count++
		for _, bearer := range bearers {
			if bytes.Contains(ev.Data, []byte(bearer)) {
				t.Error("raw bootstrap token leaked into event payload")
			}
		}
		var payload projections.APITokenCreated
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return err
		}
		seen, ok := expected[payload.TokenHash]
		if !ok || seen {
			t.Error("bootstrap token event has an unexpected or duplicate hash")
		}
		expected[payload.TokenHash] = true
		if ev.Actor == nil || ev.Actor.Subject != "trstctl:local-token-create" {
			t.Error("bootstrap event must identify the local command, not impersonate its target subject")
		}
		rec, err := st.GetAPIToken(ctx, tenantID, payload.ID)
		if err != nil {
			return err
		}
		if rec.TokenHash != payload.TokenHash || rec.Subject != payload.Subject || !slices.Equal(rec.Scopes, payload.Scopes) {
			t.Error("bootstrap token read model differs from its creation event")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != len(bearers) {
		t.Errorf("bootstrap audit recorded %d token-created events, want %d", count, len(bearers))
	}
	for _, seen := range expected {
		if !seen {
			t.Error("bootstrap credential has no immutable creation event")
		}
	}
}
