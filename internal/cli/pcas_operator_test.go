// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestPCASOperatorCommandsPreserveBodyTenantAndStatusURL(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Tenant-ID") != "tenant-a" || r.Header.Get("Authorization") != "Bearer qa-token" {
			t.Errorf("missing authenticated tenant on %s", r.URL.Path)
		}
		switch r.URL.Path {
		case "/api/v1/pcas/genesis":
			body, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") == "" ||
				!sameJSON(body, []byte(`{"identity_id":"spiffe://example/workload","algorithm":"ECDSA-P256","deployment_scope":"spiffe://example"}`)) {
				t.Errorf("genesis request %s %s body=%s", r.Method, r.URL.Path, body)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"request_id":"request-1","status":"queued","status_url":"/api/v1/pcas/requests/request-1"}`)
		case "/api/v1/pcas/requests/request-1":
			_, _ = io.WriteString(w, `{"request_id":"request-1","kind":"genesis","status":"delivered","attempts":1}`)
		case "/api/v1/pcas/chain":
			if r.URL.Query().Get("identity_id") != "spiffe://example/workload" {
				t.Errorf("chain identity query = %q", r.URL.Query().Get("identity_id"))
			}
			_, _ = io.WriteString(w, `{"identity_id":"spiffe://example/workload","count":0,"records":[]}`)
		case "/api/v1/pcas/checkpoints":
			if r.Method != http.MethodGet || r.URL.Query().Get("identity_id") != "spiffe://example/workload" {
				t.Errorf("checkpoint request %s %s", r.Method, r.URL.String())
			}
			_, _ = io.WriteString(w, `{"identity_id":"spiffe://example/workload","epoch":1,"signer_public_der":"AQID"}`)
		default:
			t.Errorf("unexpected PCAS route %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	env := cli.Env{Server: srv.URL, Token: "qa-token", Tenant: "tenant-a", HTTPClient: srv.Client()}
	if code, _, stderr := run(t, []string{"pcas", "genesis", "register"}, env, ""); code != 2 || !strings.Contains(stderr, "needs a request body") {
		t.Fatalf("bodyless genesis was not refused locally: code=%d stderr=%q", code, stderr)
	}
	if code, stdout, stderr := run(t, []string{"pcas", "genesis", "register", "-f", "-"}, env,
		`{"identity_id":"spiffe://example/workload","algorithm":"ECDSA-P256","deployment_scope":"spiffe://example"}`); code != 0 || !strings.Contains(stdout, "request-1") || stderr != "" {
		t.Fatalf("genesis command code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if code, stdout, stderr := run(t, []string{"pcas", "requests", "status", "request-1"}, env, ""); code != 0 || !strings.Contains(stdout, "delivered") || stderr != "" {
		t.Fatalf("status command code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if code, _, stderr := run(t, []string{"pcas", "chain", "get", "--identity_id", "spiffe://example/workload"}, env, ""); code != 0 || stderr != "" {
		t.Fatalf("chain command code=%d stderr=%q", code, stderr)
	}
	if code, stdout, stderr := run(t, []string{"pcas", "checkpoints", "get", "--identity_id", "spiffe://example/workload"}, env, ""); code != 0 || !strings.Contains(stdout, `"signer_public_der": "AQID"`) || stderr != "" {
		t.Fatalf("checkpoint command code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if calls != 4 {
		t.Fatalf("network calls=%d, want four authenticated operator calls", calls)
	}
}

func TestPCASBreadthCommandsReachTheirServedRoutes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		method string
		path   string
		query  string
	}{
		{"federation bridges list", []string{"pcas", "federation", "bridges", "list"}, "GET", "/api/v1/pcas/federation/bridges", ""},
		{"federation import", []string{"pcas", "federation", "imports", "request", "-f", "-"}, "POST", "/api/v1/pcas/federation/imports", ""},
		{"KEM rewrap", []string{"pcas", "kem", "rewrap", "request", "-f", "-"}, "POST", "/api/v1/pcas/kem/rewraps", ""},
		{"KEM status", []string{"pcas", "rewrap", "status", "--identity_id", "spiffe://qa/id"}, "GET", "/api/v1/pcas/rewrap", "spiffe://qa/id"},
		{"recovery policy", []string{"pcas", "recovery", "policy", "set", "-f", "-", "--force"}, "POST", "/api/v1/pcas/recovery/policies", ""},
		{"recovery successor prepare", []string{"pcas", "recovery", "successor", "prepare", "-f", "-", "--force"}, "POST", "/api/v1/pcas/recovery/successors/prepare", ""},
		{"recovery successor get", []string{"pcas", "recovery", "successor", "get", "--identity_id", "spiffe://qa/id", "--epoch", "1"}, "GET", "/api/v1/pcas/recovery/successors", "spiffe://qa/id"},
		{"recovery request", []string{"pcas", "recovery", "request", "-f", "-", "--force"}, "POST", "/api/v1/pcas/recovery/requests", ""},
		{"issuer register", []string{"pcas", "issuers", "register", "-f", "-"}, "POST", "/api/v1/pcas/issuers", ""},
		{"issuer leaf", []string{"pcas", "issuers", "leaf", "issue", "-f", "-"}, "POST", "/api/v1/pcas/issuers/leaf", ""},
		{"stapled leaf", []string{"pcas", "staple", "leaf", "issue", "-f", "-"}, "POST", "/api/v1/pcas/staple/leaf", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != tc.method || r.URL.Path != tc.path ||
					r.Header.Get("Authorization") != "Bearer qa-token" || r.Header.Get("X-Tenant-ID") != "tenant-a" {
					t.Errorf("routed request = %s %s with missing tenant auth", r.Method, r.URL.Path)
				}
				if tc.query != "" && r.URL.Query().Get("identity_id") != tc.query {
					t.Errorf("identity_id query = %q", r.URL.Query().Get("identity_id"))
				}
				if tc.name == "recovery successor get" && r.URL.Query().Get("epoch") != "1" {
					t.Errorf("recovery successor epoch query = %q", r.URL.Query().Get("epoch"))
				}
				if tc.method == "POST" {
					body, _ := io.ReadAll(r.Body)
					if r.Header.Get("Idempotency-Key") == "" || !sameJSON(body, []byte(`{"qa":"public"}`)) {
						t.Errorf("mutation missing idempotency or JSON body")
					}
				}
				_, _ = io.WriteString(w, `{}`)
			}))
			t.Cleanup(srv.Close)
			env := cli.Env{Server: srv.URL, Token: "qa-token", Tenant: "tenant-a", HTTPClient: srv.Client()}
			stdin := ""
			if tc.method == "POST" {
				stdin = `{"qa":"public"}`
			}
			if code, _, stderr := run(t, tc.args, env, stdin); code != 0 || stderr != "" || calls != 1 {
				t.Fatalf("command code=%d calls=%d stderr=%q", code, calls, stderr)
			}
		})
	}
}
