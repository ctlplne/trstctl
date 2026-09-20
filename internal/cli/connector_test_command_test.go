// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestConnectorTargetTestNeedsNoBodyAndPreservesRequestKey(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusOK, `{"status":"dry_run_queued"}`, &captured)
	env := cli.Env{Server: srv.URL, Token: "test-token", HTTPClient: srv.Client(), IdempotencyKey: "exact-test-key"}
	code, out, errOut := run(t, []string{"connector", "target", "test", "target-1"}, env, "")
	if code != 0 || errOut != "" || !strings.Contains(out, "dry_run_queued") {
		t.Fatalf("test without body: exit=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if captured.Method != http.MethodPost || captured.Path != "/api/v1/connectors/targets/target-1/test" || len(captured.Body) != 0 || captured.Header.Get("Idempotency-Key") != "exact-test-key" {
		t.Fatalf("wrong test request: %+v", captured)
	}
}

func TestConnectorDeploymentAndRollbackStillRequireCommandBody(t *testing.T) {
	for _, verb := range []string{"deploy", "rollback"} {
		t.Run(verb, func(t *testing.T) {
			var captured capture
			srv := mockServer(t, http.StatusOK, `{}`, &captured)
			code, _, errOut := run(t, []string{"connector", "target", verb, "target-1"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
			if code != 2 || !strings.Contains(errOut, "needs a request body") || captured.Method != "" {
				t.Fatalf("missing command body: exit=%d error=%q request=%+v", code, errOut, captured)
			}
		})
	}
}
