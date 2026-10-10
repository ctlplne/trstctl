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
	if calls != 3 {
		t.Fatalf("network calls=%d, want three authenticated operator calls", calls)
	}
}
