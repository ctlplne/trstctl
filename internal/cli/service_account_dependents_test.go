// SPDX-License-Identifier: BUSL-1.1
package cli_test

import (
	"net/http"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/cli"
)

func TestServiceDependentInventoryCommandsA267(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		args                     []string
	}{
		{"page", http.MethodGet, "/api/v1/access/discovery/accounts/account/dependents", "", []string{"access", "discovery", "hosts", "list", "account", "--limit", "1", "--after", "host"}},
		{"save", http.MethodPut, "/api/v1/access/discovery/accounts/account/dependents/host", `{"enabled":true}`, []string{"access", "discovery", "hosts", "save", "account", "host", "-f", "-"}},
		{"queue", http.MethodPost, "/api/v1/access/discovery/accounts/account/dependents/host/runs", "", []string{"access", "discovery", "hosts", "scan", "account", "host"}},
		{"receipt", http.MethodGet, "/api/v1/access/discovery/dependent-runs/run", "", []string{"access", "discovery", "hosts", "run", "run"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var captured capture
			server := mockServer(t, http.StatusOK, `{"status":"partial","delivery_status":"delivered"}`, &captured)
			code, out, stderr := run(t, tc.args, cli.Env{Server: server.URL, Token: "owned-inventory-token", Tenant: "tenant-a", HTTPClient: server.Client()}, tc.body)
			if code != 0 || stderr != "" || captured.Method != tc.method || captured.Path != tc.path || strings.TrimSpace(string(captured.Body)) != tc.body {
				t.Fatalf("inventory command exit=%d err=%s request=%s %s body=%s", code, stderr, captured.Method, captured.Path, captured.Body)
			}
			if (captured.Header.Get("Idempotency-Key") != "") != (tc.method != "GET") {
				t.Fatal("inventory mutation/read key mismatch")
			}
			if !strings.Contains(out, "partial") || !strings.Contains(out, "delivered") {
				t.Fatal("CLI lost coverage or delivery metadata")
			}
		})
	}
}
