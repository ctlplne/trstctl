// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestKeyCompromiseCLIReviewsExecutesAndReadsOneExactCommand(t *testing.T) {
	const identityID = "identity-1"
	var previewCall capture
	previewServer := mockServer(t, http.StatusOK,
		`{"ready":true,"effect_free":true,"preview_fingerprint":"reviewed"}`, &previewCall)
	env := cli.Env{Server: previewServer.URL, Token: "test-token", HTTPClient: previewServer.Client(),
		IdempotencyKey: "incident-one"}
	previewBody := `{"target_id":"host-target-1"}`
	code, out, errOut := run(t, []string{"identities", "compromise-preview", identityID, "-f", "-"}, env, previewBody)
	if code != 0 || errOut != "" || !strings.Contains(out, `"preview_fingerprint": "reviewed"`) {
		t.Fatalf("preview exit=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if previewCall.Method != http.MethodPost || previewCall.Path != "/api/v1/identities/identity-1/compromise/preview" ||
		string(previewCall.Body) != previewBody || previewCall.Header.Get("Idempotency-Key") != "" {
		t.Fatalf("preview request = %+v", previewCall)
	}

	var executeCall capture
	executeServer := mockServer(t, http.StatusAccepted,
		`{"revocation":{"status":"pending"},"containment":{"status":"containment_queued"}}`, &executeCall)
	env.Server, env.HTTPClient = executeServer.URL, executeServer.Client()
	executeBody := `{"identity_id":"identity-1","target_id":"host-target-1","preview_fingerprint":"reviewed"}`
	code, _, errOut = run(t, []string{"identities", "compromise", identityID, "-f", "-"}, env, executeBody)
	if code != 2 || !strings.Contains(errOut, "--force") || executeCall.Method != "" {
		t.Fatalf("unguarded compromise exit=%d stderr=%q request=%+v", code, errOut, executeCall)
	}
	code, out, errOut = run(t, []string{"--force", "identities", "compromise", identityID, "-f", "-"}, env, executeBody)
	if code != 0 || errOut != "" || !strings.Contains(out, "containment_queued") {
		t.Fatalf("compromise exit=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if executeCall.Method != http.MethodPost || executeCall.Path != "/api/v1/identities/identity-1/compromise" ||
		string(executeCall.Body) != executeBody || executeCall.Header.Get("Idempotency-Key") != "incident-one" {
		t.Fatalf("compromise request = %+v", executeCall)
	}

	var statusCall capture
	statusServer := mockServer(t, http.StatusOK,
		`{"revocation":{"status":"delivered"},"containment":{"status":"containment_stopped"}}`, &statusCall)
	env.Server, env.HTTPClient = statusServer.URL, statusServer.Client()
	code, out, errOut = run(t, []string{"identities", "compromise-status", identityID,
		"--request_key", "incident + retry"}, env, "")
	if code != 0 || errOut != "" || !strings.Contains(out, "containment_stopped") {
		t.Fatalf("status exit=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if statusCall.Method != http.MethodGet || statusCall.Path != "/api/v1/identities/identity-1/compromise" ||
		statusCall.Query != "request_key=incident+%2B+retry" ||
		statusCall.Header.Get("Idempotency-Key") != "" || len(statusCall.Body) != 0 {
		t.Fatalf("status request = %+v", statusCall)
	}
}
