// SPDX-License-Identifier: MPL-2.0

package cli_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestApprovalRequestsListReadsOnlyGenuinePendingRequests(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusOK, `{"items":[]}`, &captured)
	env := cli.Env{Server: srv.URL, Token: "approver-token", Tenant: "tenant-1", HTTPClient: srv.Client()}

	code, _, stderr := run(t, []string{"approval-requests", "list", "--status", "pending", "--limit", "100", "--cursor", "next-page"}, env, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr)
	}
	if captured.Method != http.MethodGet || captured.Path != "/api/v1/approval-requests" {
		t.Fatalf("request = %s %s, want GET /api/v1/approval-requests", captured.Method, captured.Path)
	}
	if captured.Query != (url.Values{
		"status": []string{"pending"}, "limit": []string{"100"}, "cursor": []string{"next-page"},
	}).Encode() {
		t.Fatalf("query = %q, want paginated pending queue query", captured.Query)
	}
	if len(captured.Body) != 0 || captured.Header.Get("Idempotency-Key") != "" {
		t.Fatalf("read-only approval request list sent mutation material: body=%q idempotency=%q", captured.Body, captured.Header.Get("Idempotency-Key"))
	}
}

func TestApprovalRequestsDenyBindsExactRequestDigestAndReason(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusOK, `{"id":"019fec49-6641-7131-ae7f-17f7ea4b5e0e","status":"denied","approval_count":0,"required_approvals":2}`, &captured)
	env := cli.Env{Server: srv.URL, HTTPClient: srv.Client()}

	requestID := "019fec49-6641-7131-ae7f-17f7ea4b5e0e"
	intentDigest := "sha256:8ec59a9c"
	code, _, stderr := run(t, []string{"approval-requests", "deny", requestID, intentDigest, "unsafe rollout window"}, env, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr)
	}
	if captured.Method != http.MethodPost || captured.Path != "/api/v1/approval-requests/"+requestID+"/denials" {
		t.Fatalf("request = %s %s, want exact denial route", captured.Method, captured.Path)
	}
	var body map[string]string
	if err := json.Unmarshal(captured.Body, &body); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if len(body) != 2 || body["intent_digest"] != intentDigest || body["reason"] != "unsafe rollout window" {
		t.Fatalf("body = %#v, want exact digest and denial reason", body)
	}
	if captured.Header.Get("Idempotency-Key") == "" {
		t.Fatal("denial mutation did not send an Idempotency-Key")
	}
}

func TestApprovalRequestsApproveBindsExactRequestIDAndIntentDigest(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusOK, `{"id":"019fec49-6641-7131-ae7f-17f7ea4b5e0e","status":"pending","approval_count":1,"required_approvals":2}`, &captured)
	env := cli.Env{Server: srv.URL, HTTPClient: srv.Client()}

	requestID := "019fec49-6641-7131-ae7f-17f7ea4b5e0e"
	intentDigest := "sha256:8ec59a9c"
	code, _, stderr := run(t, []string{"approval-requests", "approve", requestID, intentDigest}, env, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr)
	}
	if captured.Method != http.MethodPost || captured.Path != "/api/v1/approval-requests/"+requestID+"/approvals" {
		t.Fatalf("request = %s %s, want exact approval-request route", captured.Method, captured.Path)
	}
	var body map[string]string
	if err := json.Unmarshal(captured.Body, &body); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if len(body) != 1 || body["intent_digest"] != intentDigest {
		t.Fatalf("body = %#v, want only exact intent_digest", body)
	}
	if captured.Header.Get("Idempotency-Key") == "" {
		t.Fatal("approval mutation did not send an Idempotency-Key")
	}
}
