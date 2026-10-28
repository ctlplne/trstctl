// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestSSHTrustFleetPreviewIsReadOnlyAndStartIsIdempotent(t *testing.T) {
	for _, entry := range []struct {
		name, path string
		read       bool
		status     int
	}{
		{"preview", "/api/v1/ssh/trust-fleet/preview", true, 200},
		{"request-approval", "/api/v1/ssh/trust-fleet/approvals", false, 201},
		{"start", "/api/v1/ssh/trust-fleet/rollouts", false, 202},
	} {
		t.Run(entry.name, func(t *testing.T) {
			var captured capture
			server := mockServer(t, entry.status, `{"state":"pending"}`, &captured)
			env := cli.Env{Server: server.URL, HTTPClient: server.Client()}
			code, _, stderr := run(t, []string{"ssh", "trust-fleet", entry.name, "-f", "-"}, env, `{"plan_digest":"sha256:reviewed"}`)
			if code != 0 || captured.Method != http.MethodPost || captured.Path != entry.path {
				t.Fatalf("command=%d %s request=%s %s", code, stderr, captured.Method, captured.Path)
			}
			if entry.read && captured.Header.Get("Idempotency-Key") != "" {
				t.Fatal("preview reserved a mutation key")
			}
			if !entry.read && captured.Header.Get("Idempotency-Key") == "" {
				t.Fatal("mutation omitted its idempotency key")
			}
		})
	}
}
