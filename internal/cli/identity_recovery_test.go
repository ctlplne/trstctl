// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestIdentityIssuanceRetryPreservesOriginalRequestAndRecoveryKey(t *testing.T) {
	const body = `{"request_key":"original + & issuance","reason":"Restored the configured CA connection"}`
	var captured capture
	srv := mockServer(t, http.StatusAccepted,
		`{"identity_id":"identity-1","request_key":"original + & issuance","retry_event_id":"grant-1","state":"pending","attempts":10,"attempt_grant":1}`, &captured)
	env := cli.Env{Server: srv.URL, Token: "issuer-token", Tenant: "tenant-a", HTTPClient: srv.Client()}
	args := []string{"--idempotency-key", "recover-original-once", "identities", "issuance-retry", "identity-1", "-f", "-"}
	for attempt := 0; attempt < 2; attempt++ {
		code, stdout, stderr := run(t, args, env, body)
		if code != 0 || stderr != "" || !strings.Contains(stdout, `"retry_event_id": "grant-1"`) || !strings.Contains(stdout, `"state": "pending"`) {
			t.Fatalf("retry invocation %d = exit %d stdout=%q stderr=%q", attempt, code, stdout, stderr)
		}
		if captured.Method != http.MethodPost || captured.Path != "/api/v1/identities/identity-1/issuance-retry" ||
			captured.Header.Get("Idempotency-Key") != "recover-original-once" || !sameJSON(captured.Body, []byte(body)) {
			t.Fatalf("retry request = %s %s key=%q body=%s", captured.Method, captured.Path, captured.Header.Get("Idempotency-Key"), captured.Body)
		}
		if captured.Header.Get("Authorization") != "Bearer issuer-token" || captured.Header.Get("X-Tenant-ID") != "tenant-a" {
			t.Fatal("issuance recovery must carry the caller's authentication and tenant")
		}
	}
}

func TestIdentityIssuanceRetryReportsServerRefusal(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusConflict,
		`{"type":"about:blank","title":"Conflict","status":409,"detail":"identity has advanced beyond the original issuance"}`, &captured)
	env := cli.Env{Server: srv.URL, Token: "issuer-token", Tenant: "tenant-a", HTTPClient: srv.Client()}
	code, stdout, stderr := run(t,
		[]string{"--idempotency-key", "recover-original-once", "identities", "issuance-retry", "identity-1", "-f", "-"},
		env, `{"request_key":"original-issuance","reason":"Restored the configured CA connection"}`)
	if code != 1 || !strings.Contains(stdout, `"status": 409`) || !strings.Contains(stdout, "identity has advanced beyond the original issuance") || !strings.Contains(stderr, "server returned status 409") {
		t.Fatalf("refused recovery = exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestIdentityDeploymentEvidenceReadsTheRequestedIdentityWithoutMutation(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusOK,
		`{"identity_id":"retired-identity","read_at":"2026-09-13T16:35:32Z","receipt":{"status":"rolled_back","fingerprint":"predecessor-fingerprint"},"certificate":{"id":"predecessor-certificate","status":"revoked"}}`, &captured)
	env := cli.Env{Server: srv.URL, Token: "reader-token", Tenant: "tenant-a", HTTPClient: srv.Client()}
	code, stdout, stderr := run(t, []string{"identities", "deployment-evidence", "retired-identity"}, env, "")
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"id": "predecessor-certificate"`) || !strings.Contains(stdout, `"status": "revoked"`) {
		t.Fatalf("deployment evidence = exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if captured.Method != http.MethodGet || captured.Path != "/api/v1/identities/retired-identity/deployment-evidence" ||
		captured.Query != "" || captured.Header.Get("Idempotency-Key") != "" || len(captured.Body) != 0 {
		t.Fatalf("deployment evidence request = %s %s query=%q key=%q body=%s", captured.Method, captured.Path, captured.Query, captured.Header.Get("Idempotency-Key"), captured.Body)
	}
	if captured.Header.Get("Authorization") != "Bearer reader-token" || captured.Header.Get("X-Tenant-ID") != "tenant-a" {
		t.Fatal("deployment evidence must carry the caller's authentication and tenant")
	}
}
