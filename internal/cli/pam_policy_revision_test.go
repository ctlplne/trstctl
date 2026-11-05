// SPDX-License-Identifier: BUSL-1.1
package cli_test

import (
	"net/http"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/cli"
)

func TestAccountPolicyDeleteRequiresAndSendsReadRevision(t *testing.T) {
	for _, family := range []string{"folders", "auto-approval-rules"} {
		t.Run(family, func(t *testing.T) {
			var captured capture
			srv := mockServer(t, http.StatusOK, `{"deleted":true}`, &captured)
			env := cli.Env{Server: srv.URL, HTTPClient: srv.Client()}
			code, _, stderr := run(t, []string{"access", family, "delete", "policy-id", "--revision", "4", "--force"}, env, "")
			if code != 0 {
				t.Fatalf("delete at read revision: exit=%d stderr=%s", code, stderr)
			}
			if captured.Method != http.MethodDelete || captured.Path != "/api/v1/access/"+family+"/policy-id" || captured.Query != "revision=4" || captured.Header.Get("Idempotency-Key") == "" {
				t.Fatalf("delete did not bind exact revision: %+v", captured)
			}
			captured = capture{}
			code, _, stderr = run(t, []string{"access", family, "delete", "policy-id", "--force"}, env, "")
			if code == 0 || !strings.Contains(stderr, "requires --revision") || captured.Method != "" {
				t.Fatalf("missing revision reached transport: exit=%d stderr=%s captured=%+v", code, stderr, captured)
			}
		})
	}
}
