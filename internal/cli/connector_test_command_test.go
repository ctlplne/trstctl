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

func TestConnectorContainmentReviewAndSubmitUseExactRoutes(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusOK, `{"ready":true,"preview_fingerprint":"reviewed"}`, &captured)
	env := cli.Env{Server: srv.URL, Token: "test-token", HTTPClient: srv.Client(), IdempotencyKey: "exact-containment-key"}
	code, out, errOut := run(t, []string{"connector", "target", "contain-preview", "target-1"}, env, "")
	if code != 0 || errOut != "" || !strings.Contains(out, "reviewed") {
		t.Fatalf("containment preview: exit=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if captured.Method != http.MethodGet || captured.Path != "/api/v1/connectors/targets/target-1/contain/preview" || len(captured.Body) != 0 || captured.Header.Get("Idempotency-Key") != "" {
		t.Fatalf("wrong containment preview request: %+v", captured)
	}

	request := `{"target_revision":"revision-1","identity_id":"identity-1","expected_fingerprint":"leaf-1","required_agent_id":"agent-1","preview_fingerprint":"reviewed","reason":"confirmed compromise"}`
	server := mockServer(t, http.StatusAccepted, `{"status":"containment_queued"}`, &captured)
	env.Server, env.HTTPClient = server.URL, server.Client()
	code, out, errOut = run(t, []string{"--force", "connector", "target", "contain", "target-1", "-f", "-"}, env, request)
	if code != 0 || errOut != "" || !strings.Contains(out, "containment_queued") {
		t.Fatalf("containment submit: exit=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if captured.Method != http.MethodPost || captured.Path != "/api/v1/connectors/targets/target-1/contain" || string(captured.Body) != request || captured.Header.Get("Idempotency-Key") != "exact-containment-key" {
		t.Fatalf("wrong containment submit request: %+v", captured)
	}
}

func TestConnectorContainmentNeedsExplicitForce(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusAccepted, `{}`, &captured)
	code, _, errOut := run(t, []string{"connector", "target", "contain", "target-1", "-f", "-"},
		cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, `{ "reason": "test" }`)
	if code != 2 || !strings.Contains(errOut, "--force") || captured.Method != "" {
		t.Fatalf("containment without force: exit=%d error=%q request=%+v", code, errOut, captured)
	}
}

func TestConnectorContainmentSubmitRequiresReviewedBody(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusAccepted, `{}`, &captured)
	code, _, errOut := run(t, []string{"connector", "target", "contain", "target-1"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 2 || !strings.Contains(errOut, "needs a request body") || captured.Method != "" {
		t.Fatalf("missing reviewed body: exit=%d error=%q request=%+v", code, errOut, captured)
	}
}
