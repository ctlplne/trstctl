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

func TestServiceDependentRotationCommandsA267(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		args                     []string
	}{
		{"preview", "POST", "/api/v1/access/discovery/accounts/account/dependents/rotations/preview", `{"secret_name":"ad/svc","order":[],"probes":[]}`, []string{"access", "discovery", "rotation", "preview", "account", "-f", "-"}},
		{"pending", "GET", "/api/v1/access/discovery/accounts/account/dependents/rotations/reviews/change", "", []string{"access", "discovery", "rotation", "pending", "account", "change", "--approval-request-id", "review"}},
		{"approval", "POST", "/api/v1/access/discovery/accounts/account/dependents/rotations/approval", `{"intent_digest":"reviewed","reason":"repair drift"}`, []string{"access", "discovery", "rotation", "approval", "account", "-f", "-"}},
		{"review", "GET", "/api/v1/access/discovery/reconciliation-reviews/change", "", []string{"access", "discovery", "rotation", "review", "change"}},
		{"queue", "POST", "/api/v1/access/discovery/accounts/account/dependents/rotations", `{"intent_digest":"reviewed","acknowledge_single_phase":true}`, []string{"access", "discovery", "rotation", "queue", "account", "-f", "-"}},
		{"get", "GET", "/api/v1/access/discovery/dependent-rotations/change", "", []string{"access", "discovery", "rotation", "get", "change"}},
		{"recovery-preview", "GET", "/api/v1/access/discovery/dependent-rotations/change/recoveries/preview", "", []string{"access", "discovery", "rotation", "recovery-preview", "change", "--step-id", "step"}},
		{"recovery-queue", "POST", "/api/v1/access/discovery/dependent-rotations/change/recoveries", `{"step_id":"step","reason":"observed terminal","acknowledge_original_outcome":true}`, []string{"access", "discovery", "rotation", "recovery-queue", "change", "-f", "-", "--force"}},
		{"steps", "GET", "/api/v1/access/discovery/dependent-rotations/change/steps", "", []string{"access", "discovery", "rotation", "steps", "change", "--limit", "1", "--after", "step"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var captured capture
			server := mockServer(t, http.StatusOK, `{"status":"uncertain","delivery_status":"failed"}`, &captured)
			code, out, stderr := run(t, tc.args, cli.Env{Server: server.URL, Token: "owned-token", Tenant: "tenant-a", HTTPClient: server.Client()}, tc.body)
			if code != 0 || stderr != "" || captured.Method != tc.method || captured.Path != tc.path || strings.TrimSpace(string(captured.Body)) != tc.body {
				t.Fatalf("exit=%d err=%s request=%s %s body=%s", code, stderr, captured.Method, captured.Path, captured.Body)
			}
			if (captured.Header.Get("Idempotency-Key") != "") != (tc.method != "GET") {
				t.Fatal("rotation mutation/read key mismatch")
			}
			if !strings.Contains(out, "uncertain") || !strings.Contains(out, "failed") {
				t.Fatal("CLI lost native uncertainty or delivery status")
			}
			if tc.name == "pending" && captured.Query != "approval_request_id=review" {
				t.Fatal("pending review lost its exact approval request")
			}
			if tc.name == "recovery-preview" && captured.Query != "step_id=step" {
				t.Fatal("exact recovery step query lost")
			}
			if tc.name == "steps" && captured.Query != "after=step&limit=1" {
				t.Fatal("step cursor lost")
			}
		})
	}
}

func TestInverseRecoveryCLIRequiresExplicitForceA267(t *testing.T) {
	var captured capture
	server := mockServer(t, http.StatusAccepted, `{}`, &captured)
	code, _, stderr := run(t, []string{"access", "discovery", "rotation", "recovery-queue", "change", "-f", "-"}, cli.Env{Server: server.URL, Token: "owned-token", Tenant: "owned-tenant", HTTPClient: server.Client()}, `{"step_id":"step"}`)
	if code != 2 || !strings.Contains(stderr, "--force") || captured.Method != "" {
		t.Fatal("inverse native recovery reached server without explicit force")
	}
}
