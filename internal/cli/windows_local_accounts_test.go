// SPDX-License-Identifier: BUSL-1.1
package cli_test

import (
	"net/http"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/cli"
)

func TestWindowsLocalAccountInventoryCommandsA268(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		args         []string
	}{
		{"GET", "/api/v1/access/discovery/windows-hosts", []string{"access", "discovery", "windows-local", "hosts", "--limit", "1", "--after", "host"}},
		{"POST", "/api/v1/access/discovery/windows-hosts/host/local-administrators/runs", []string{"access", "discovery", "windows-local", "scan", "host"}},
		{"GET", "/api/v1/access/discovery/windows-hosts/host/local-administrators/runs", []string{"access", "discovery", "windows-local", "runs", "host", "--limit", "1", "--after", "run"}},
		{"GET", "/api/v1/access/discovery/windows-hosts/host/local-administrators/runs/run", []string{"access", "discovery", "windows-local", "run", "host", "run"}},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var captured capture
			server := mockServer(t, http.StatusOK, `{"status":"queued","delivery_status":"pending"}`, &captured)
			code, out, stderr := run(t, tc.args, cli.Env{Server: server.URL, Token: "inventory-reader-token", Tenant: "tenant-a", HTTPClient: server.Client()}, "")
			if code != 0 || stderr != "" || captured.Method != tc.method || captured.Path != tc.path || len(captured.Body) != 0 {
				t.Fatalf("local inventory CLI mismatch exit=%d err=%s request=%s %s", code, stderr, captured.Method, captured.Path)
			}
			if (captured.Header.Get("Idempotency-Key") != "") != (tc.method == "POST") {
				t.Fatal("local inventory mutation key mismatch")
			}
			if !strings.Contains(out, "queued") || !strings.Contains(out, "pending") {
				t.Fatal("CLI lost delivery state")
			}
		})
	}
}
