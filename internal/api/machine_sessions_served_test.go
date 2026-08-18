// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

/* C-S3 (07-closeout plan, DA-02) served proof against real PostgreSQL (RLS)
 * and a real embedded JetStream event log: login issues a ledger event, the
 * ledger lists it, revocation is an idempotent event-sourced mutation, and the
 * per-tenant method overlay is enforced at the login exchange itself. */

const (
	msTenantA = "11111111-1111-1111-1111-111111111111"
	msTenantB = "22222222-2222-2222-2222-222222222222"
)

func startMachineSessionPostgres(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	dir, err := os.MkdirTemp("", "trstctl-ms-pg-*")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	runtime := filepath.Join(dir, "runtime")
	data := filepath.Join(dir, "data")
	for _, path := range []string{bin, runtime, data} {
		if err := os.MkdirAll(path, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
			t.Fatal(err)
		}
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Username("postgres").Password("postgres").Database("postgres").
		Port(uint32(port)).RuntimePath(runtime).DataPath(data).BinariesPath(bin)) // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
	if err := db.Start(); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		t.Skip("embedded postgres unavailable")
	}
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", port), func() {
		_ = db.Stop()
		_ = os.RemoveAll(dir)
	}
}

type machineSessionHarness struct {
	handler http.Handler
	token   authmethod.TokenMethod
}

func newMachineSessionHarness(t *testing.T) *machineSessionHarness {
	t.Helper()
	ctx := context.Background()

	dsn, stopPG := startMachineSessionPostgres(t)
	t.Cleanup(stopPG)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	authSecret := []byte("served-machine-auth-secret")
	handler := api.New(st, orchestrator.NewMemoryIdempotency(), nil,
		api.WithInsecureHeaderResolver(),
		api.WithEventLog(log),
		api.WithSecrets(api.SecretsBackend{
			Store:      st,
			AuthSecret: authSecret,
			SessionTTL: time.Hour,
		}),
	)
	return &machineSessionHarness{
		handler: handler,
		token:   authmethod.TokenMethod{Secret: authSecret, TenantID: msTenantA},
	}
}

func (h *machineSessionHarness) do(t *testing.T, method, path, tenantID, idemKey string, body any) (int, []byte) {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = strings.NewReader(string(raw))
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Roles", "admin")
	req.Header.Set("X-Subject", "operator-1")
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (h *machineSessionHarness) login(t *testing.T, principal string) (int, map[string]any) {
	t.Helper()
	credential, err := h.token.Issue(principal, time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("issue token credential: %v", err)
	}
	status, body := h.do(t, http.MethodPost, "/api/v1/secrets/login", msTenantA, "", map[string]any{
		"method": "token", "credential": credential,
	})
	var out map[string]any
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode login: %v; body=%s", err, body)
		}
	}
	return status, out
}

func listSessions(t *testing.T, h *machineSessionHarness, tenantID string) []map[string]any {
	t.Helper()
	status, body := h.do(t, http.MethodGet, "/api/v1/secrets/sessions", tenantID, "", nil)
	if status != http.StatusOK {
		t.Fatalf("list sessions = %d; body=%s", status, body)
	}
	var out struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	return out.Items
}

func TestMachineSessionLedgerServed(t *testing.T) {
	if testing.Short() {
		t.Skip("served machine-session test needs embedded postgres")
	}
	h := newMachineSessionHarness(t)

	// 1. Login issues a session AND a ledger row (secrets.session.started).
	status, login := h.login(t, "payments-bot")
	if status != http.StatusOK {
		t.Fatalf("machine login = %d", status)
	}
	sessionID, _ := login["session_id"].(string)
	if sessionID == "" {
		t.Fatalf("login response missing session_id: %v", login)
	}
	items := listSessions(t, h, msTenantA)
	if len(items) != 1 || items[0]["id"] != sessionID || items[0]["principal"] != "payments-bot" || items[0]["status"] != "active" {
		t.Fatalf("ledger after login = %v", items)
	}

	// 2. Tenant isolation: tenant B sees an empty ledger (RLS, AN-1).
	if other := listSessions(t, h, msTenantB); len(other) != 0 {
		t.Fatalf("tenant-b ledger should be empty, got %v", other)
	}

	// 3. Revocation is an idempotent event-sourced mutation (AN-5, AN-2).
	revokePath := "/api/v1/secrets/sessions/" + sessionID + "/revoke"
	status, body := h.do(t, http.MethodPost, revokePath, msTenantA, "revoke-key-1", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"revoked"`) {
		t.Fatalf("revoke = %d; body=%s", status, body)
	}
	// Same idempotency key: identical replay.
	replayStatus, replayBody := h.do(t, http.MethodPost, revokePath, msTenantA, "revoke-key-1", nil)
	if replayStatus != status || string(replayBody) != string(body) {
		t.Fatalf("revoke replay mismatch: %d/%s vs %d/%s", replayStatus, replayBody, status, body)
	}
	// Fresh key: the apply itself is idempotent — still revoked, original facts kept.
	status2, body2 := h.do(t, http.MethodPost, revokePath, msTenantA, "revoke-key-2", nil)
	if status2 != http.StatusOK || !strings.Contains(string(body2), `"revoked"`) {
		t.Fatalf("second revoke = %d; body=%s", status2, body2)
	}
	items = listSessions(t, h, msTenantA)
	if len(items) != 1 || items[0]["status"] != "revoked" || items[0]["revoked_by"] != "operator-1" {
		t.Fatalf("ledger after revoke = %v", items)
	}

	// 4. Missing Idempotency-Key is refused (AN-5).
	if noKeyStatus, _ := h.do(t, http.MethodPost, revokePath, msTenantA, "", nil); noKeyStatus != http.StatusBadRequest {
		t.Fatalf("revoke without idempotency key = %d, want 400", noKeyStatus)
	}

	// 5. Disable overlay: refused at the login exchange itself.
	status, body = h.do(t, http.MethodPost, "/api/v1/secrets/auth-methods/token/disable", msTenantA, "disable-key-1", nil)
	if status != http.StatusOK {
		t.Fatalf("disable method = %d; body=%s", status, body)
	}
	if loginStatus, _ := h.login(t, "payments-bot"); loginStatus == http.StatusOK {
		t.Fatalf("login against a disabled method succeeded")
	}
	// The projection reflects the overlay.
	status, body = h.do(t, http.MethodGet, "/api/v1/secrets/auth-methods", msTenantA, "", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"disabled":true`) {
		t.Fatalf("auth-methods after disable = %d; body=%s", status, body)
	}

	// 6. Re-enable restores the exchange.
	if status, body = h.do(t, http.MethodPost, "/api/v1/secrets/auth-methods/token/enable", msTenantA, "enable-key-1", nil); status != http.StatusOK {
		t.Fatalf("enable method = %d; body=%s", status, body)
	}
	if loginStatus, _ := h.login(t, "payments-bot"); loginStatus != http.StatusOK {
		t.Fatalf("login after re-enable = %d, want 200", loginStatus)
	}

	// 7. Unknown method names are refused, not silently recorded.
	if status, _ = h.do(t, http.MethodPost, "/api/v1/secrets/auth-methods/nonsense/disable", msTenantA, "disable-key-2", nil); status != http.StatusNotFound {
		t.Fatalf("disable unknown method = %d, want 404", status)
	}
}

func TestMachineSessionLedgerHonestWhenNotConfigured(t *testing.T) {
	// Without the event log + store, the login exchange still works (pre-C-S3
	// behavior) and the ledger says it is not enabled instead of serving an
	// empty list.
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver(), api.WithSecrets(api.SecretsBackend{
		AuthSecret: []byte("unit-secret"),
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/sessions", nil)
	req.Header.Set("X-Tenant-ID", msTenantA)
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "ledger requires") {
		t.Fatalf("unconfigured ledger = %d; body=%s", rec.Code, rec.Body.String())
	}
}
