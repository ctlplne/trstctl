package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
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
// the control plane is not live at the same time. This test mirrors that by giving
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
	dsn, stopPG, err := startBundledPostgres(config.Postgres{Mode: config.PostgresBundled, DataDir: t.TempDir(), Port: freeTCPPort(t)})
	if err != nil {
		t.Fatalf("start bundled postgres: %v", err)
	}
	t.Cleanup(func() { _ = stopPG() })

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
	bootCfg.NATS = config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}

	raw, err := RunTokenCreate(ctx, bootCfg, TokenCreateOptions{TenantID: tenantA, TenantName: "Acme", Subject: "ci-bot"})
	if err != nil {
		t.Fatalf("RunTokenCreate: %v", err)
	}
	if !strings.HasPrefix(raw, "trst_") {
		t.Fatalf("bootstrap token %q does not carry the trst_ prefix", raw)
	}

	// RED-004 guard: the bootstrap token must NOT carry issuance authority. The
	// default scope set withholds certs:issue (it only creates an API credential).
	for _, s := range BootstrapAdminScopes() {
		if s == "certs:issue" {
			t.Fatal("bootstrap default scopes include certs:issue; the first token must not open self-issue (RED-004)")
		}
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
		code, body := get(raw)
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
