// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestIdentityListCLIForwardsSearchAndCompleteSummary(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusOK, `{"items":[],"next_cursor":"","summary":{"total":41,"by_status":{"issued":10,"revoked":11}}}`, &captured)
	env := cli.Env{Server: srv.URL, Token: "list-fixture", Tenant: "tenant-a", HTTPClient: srv.Client()}
	code, stdout, stderr := run(t, []string{"identities", "list", "--limit", "1", "--q", "qa-bulk-console", "--kind", "x509", "--include_summary", "true"}, env, "")
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"total": 41`) {
		t.Fatalf("identity list exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	want := url.Values{"limit": {"1"}, "q": {"qa-bulk-console"}, "kind": {"x509"}, "include_summary": {"true"}}.Encode()
	if captured.Method != http.MethodGet || captured.Path != "/api/v1/identities" || captured.Query != want || captured.Header.Get("Idempotency-Key") != "" || len(captured.Body) != 0 {
		t.Fatalf("identity list request = %s %s?%s key=%q body=%s", captured.Method, captured.Path, captured.Query, captured.Header.Get("Idempotency-Key"), captured.Body)
	}
}
