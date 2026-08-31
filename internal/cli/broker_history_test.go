// SPDX-License-Identifier: MPL-2.0

package cli_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestWorkloadCLIHandsOffExactSignedIDAndPreservesAbsentLegacyFields(t *testing.T) {
	const signedID = "spiffe://served.test/_trstctl/v1/tenant/11111111-1111-4111-8111-111111111111/attested/method/k8s_sat/subject/ns/QA/sa/Web"
	for _, tc := range []struct {
		name, method, path string
		args               []string
		list               bool
	}{
		{"attested", http.MethodPost, "/api/v1/workloads/attested-issuance", []string{"workloads", "attested-issuance", "-f", "-"}, false},
		{"broker", http.MethodPost, "/api/v1/broker/agent-identities", []string{"broker", "agent-identities", "issue", "-f", "-"}, false},
		{"ephemeral", http.MethodPost, "/api/v1/ephemeral", []string{"ephemeral", "issue", "-f", "-"}, false},
		{"history-detail", http.MethodGet, "/api/v1/broker/agent-identities/certificate-7", []string{"broker", "agent-identities", "get", "certificate-7"}, false},
		{"history-list", http.MethodGet, "/api/v1/broker/agent-identities", []string{"broker", "agent-identities", "list"}, true},
	} {
		for _, retained := range []bool{false, true} {
			name := tc.name + "/current"
			if retained {
				name = tc.name + "/retained-without-field"
			}
			t.Run(name, func(t *testing.T) {
				// Transport fixtures, not proof of signing. Served tests compare
				// the real leaf; this verifies CLI output does not truncate, rename
				// or invent optional response fields for machine consumers.
				row := map[string]any{"subject": "friendly-label", "certificate_id": "certificate-7"}
				if !retained {
					row["spiffe_id"] = signedID
				}
				var want any = row
				if tc.list {
					want = map[string]any{"items": []any{row}, "next_cursor": ""}
				}
				body, err := json.Marshal(want)
				if err != nil {
					t.Fatal(err)
				}
				var captured capture
				srv := mockServer(t, http.StatusOK, string(body), &captured)
				code, stdout, stderr := run(t, tc.args, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "{}")
				if code != 0 || stderr != "" {
					t.Fatalf("handoff exit=%d stderr=%q", code, stderr)
				}
				var got any
				if err := json.Unmarshal([]byte(stdout), &got); err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("CLI changed exact identity or invented legacy metadata: %v", err)
				}
				if captured.Method != tc.method || captured.Path != tc.path {
					t.Fatal("CLI used another workload route")
				}
				if (captured.Header.Get("Idempotency-Key") != "") != (tc.method == http.MethodPost) {
					t.Fatal("CLI changed read/mutation idempotency semantics")
				}
			})
		}
	}
}

func TestBrokerHistoryCLIUsesReadOnlyInventoryAndPreservesQuery(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusOK, `{"items":[],"next_cursor":"next","generated_at":"2026-08-31T12:00:00Z","projection_state":"catching_up","history_scope":"broker_issued_certificates"}`, &captured)
	env := cli.Env{Server: srv.URL, Token: "history-fixture", Tenant: "tenant-a", HTTPClient: srv.Client()}
	code, stdout, stderr := run(t, []string{"broker", "agent-identities", "list", "--limit", "5", "--cursor", "cursor-7", "--q", "agent & build", "--method", "k8s_sat", "--state", "expired"}, env, "")
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"projection_state": "catching_up"`) {
		t.Fatalf("list exit=%d stderr=%q", code, stderr)
	}
	q, err := url.ParseQuery(captured.Query)
	if err != nil || q.Get("limit") != "5" || q.Get("cursor") != "cursor-7" || q.Get("q") != "agent & build" || q.Get("method") != "k8s_sat" || q.Get("state") != "expired" {
		t.Fatalf("history filters changed: %s", captured.Query)
	}
	if captured.Method != http.MethodGet || captured.Path != "/api/v1/broker/agent-identities" || captured.Header.Get("Idempotency-Key") != "" || len(captured.Body) != 0 {
		t.Fatal("history list was not a read")
	}
	code, _, stderr = run(t, []string{"broker", "agent-identities", "get", "certificate-7"}, env, "")
	if code != 0 || stderr != "" || captured.Method != http.MethodGet || captured.Path != "/api/v1/broker/agent-identities/certificate-7" || captured.Header.Get("Idempotency-Key") != "" {
		t.Fatalf("detail was not a read: exit=%d stderr=%q", code, stderr)
	}
}
