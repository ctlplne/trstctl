// SPDX-License-Identifier: MPL-2.0

package cli_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

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
