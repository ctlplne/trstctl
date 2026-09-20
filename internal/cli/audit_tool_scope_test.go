// SPDX-License-Identifier: BUSL-1.1
package cli_test

import (
	"net/http"
	"net/url"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestAuditCommandsPreserveToolFeatureActionAndAsOf(t *testing.T) {
	for _, command := range []string{"events", "export"} {
		t.Run(command, func(t *testing.T) {
			var captured capture
			server := mockServer(t, http.StatusOK, `{"events":[]}`, &captured)
			args := []string{"audit", command, "--tool", "workloads_machines", "--feature_id", "F30", "--action", "upsert_trust", "--as_of", "12", "--q", "payments", "--limit", "2"}
			code, _, stderr := run(t, args, cli.Env{Server: server.URL, HTTPClient: server.Client()}, "")
			if code != 0 {
				t.Fatalf("audit %s: code=%d stderr=%s", command, code, stderr)
			}
			params, err := url.ParseQuery(captured.Query)
			if err != nil {
				t.Fatal(err)
			}
			for k, want := range map[string]string{"tool": "workloads_machines", "feature_id": "F30", "action": "upsert_trust", "as_of": "12", "q": "payments", "limit": "2"} {
				if got := params.Get(k); got != want {
					t.Errorf("%s %s=%q want %q", command, k, got, want)
				}
			}
			if captured.Method != http.MethodGet || captured.Header.Get("Idempotency-Key") != "" {
				t.Fatal("audit read became a mutation")
			}
		})
	}
}
