// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestBrokerPreviewUsesReadOnlyPOSTWithoutRecoveryKey(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusOK, `{"ready":true,"effect_free":true,"effective_ttl_seconds":120}`, &captured)
	env := cli.Env{Server: srv.URL, Token: "preview-fixture", Tenant: "tenant-a", HTTPClient: srv.Client()}
	body := `{"agent_id":"agent-7","method":"k8s_sat","payload_base64":"cHJvb2Y=","public_key_pem":"public-key-fixture","scopes":["tool:inventory.read"],"ttl_seconds":120}`
	code, stdout, stderr := run(t, []string{"broker", "agent-identities", "preview", "-f", "-"}, env, body)
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"effect_free": true`) {
		t.Fatalf("preview exit=%d stderr=%q", code, stderr)
	}
	if captured.Method != http.MethodPost || captured.Path != "/api/v1/broker/agent-identities/preview" || captured.Header.Get("Idempotency-Key") != "" || !sameJSON(captured.Body, []byte(body)) {
		t.Fatal("preview changed the command or sent a mutation recovery key")
	}
}
