// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestAgentDelegationCommandsCoverServedRouteFamily(t *testing.T) {
	want := map[string]string{ // #nosec G101 -- API route names are public identifiers, not credential values (CWE-798)
		"agent-delegation roots register":              "POST /api/v1/agent-delegation/root-anchors",
		"agent-delegation roots list":                  "GET /api/v1/agent-delegation/root-anchors",
		"agent-delegation issue":                       "POST /api/v1/agent-delegation/issuances",
		"agent-delegation issuance get":                "GET /api/v1/agent-delegation/issuance",
		"agent-delegation revoke":                      "POST /api/v1/agent-delegation/revocations",
		"agent-delegation chain get":                   "GET /api/v1/agent-delegation/chain",
		"agent-delegation credential get":              "GET /api/v1/agent-delegation/credential",
		"agent-delegation revocations incomplete-jobs": "GET /api/v1/agent-delegation/revocations/incomplete-jobs",
		"agent-delegation revocations evidence":        "GET /api/v1/agent-delegation/revocations/evidence",
	}
	got := map[string]cli.Command{}
	for _, command := range cli.Commands() {
		got[strings.Join(command.Name, " ")] = command
	}
	for name, route := range want {
		command, ok := got[name]
		if !ok {
			t.Errorf("missing %s", name)
			continue
		}
		if command.Method+" "+command.Path != route {
			t.Errorf("%s maps to %s %s, want %s", name, command.Method, command.Path, route)
		}
	}
}

func TestAgentDelegationRootRegisterHelpExplainsImmutableBinding(t *testing.T) {
	code, stdout, stderr := run(t, []string{"agent-delegation", "roots", "register", "--help"}, cli.Env{}, "")
	if code != 0 || stderr != "" {
		t.Fatalf("root register help code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "new key ID") || !strings.Contains(stdout, "immutable") || strings.Contains(stdout, "or update") {
		t.Fatalf("root register help implies an in-place trust change: %q", stdout)
	}
}

func TestAgentDelegationCommandsCarryTenantBodyAndRequiredReadIDs(t *testing.T) {
	var registered capture
	server := mockServer(t, http.StatusOK, `{"key_id":"qa-root"}`, &registered)
	env := cli.Env{Server: server.URL, Token: "qa-token", Tenant: "tenant-a", HTTPClient: server.Client()}
	body := `{"key_id":"qa-root","public_pem":"public-only","auth_ref":"qa"}`
	if code, _, stderr := run(t, []string{"agent-delegation", "roots", "register", "-f", "-"}, env, body); code != 0 || stderr != "" {
		t.Fatalf("register code=%d stderr=%q", code, stderr)
	}
	if registered.Method != http.MethodPost || registered.Path != "/api/v1/agent-delegation/root-anchors" ||
		registered.Header.Get("Authorization") != "Bearer qa-token" || registered.Header.Get("X-Tenant-ID") != "tenant-a" ||
		registered.Header.Get("Idempotency-Key") == "" || !sameJSON(registered.Body, []byte(body)) {
		t.Fatalf("register request method=%s path=%s tenant=%q key_present=%t body_matches=%t", registered.Method, registered.Path,
			registered.Header.Get("X-Tenant-ID"), registered.Header.Get("Idempotency-Key") != "", sameJSON(registered.Body, []byte(body)))
	}

	var read capture
	readServer := mockServer(t, http.StatusOK, `{"credential_id":"agent:qa/credential"}`, &read)
	readEnv := cli.Env{Server: readServer.URL, Token: "qa-token", Tenant: "tenant-a", HTTPClient: readServer.Client()}
	if code, _, stderr := run(t, []string{"agent-delegation", "credential", "get"}, readEnv, ""); code != 2 || !strings.Contains(stderr, "--credential_id") {
		t.Fatalf("missing credential id code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr := run(t, []string{"agent-delegation", "credential", "get", "--credential_id", "agent:qa/credential"}, readEnv, ""); code != 0 || stderr != "" {
		t.Fatalf("credential get code=%d stderr=%q", code, stderr)
	}
	if read.Method != http.MethodGet || read.Path != "/api/v1/agent-delegation/credential" || read.Query != "credential_id=agent%3Aqa%2Fcredential" ||
		read.Header.Get("Idempotency-Key") != "" || len(read.Body) != 0 {
		t.Fatalf("credential read method=%s path=%s query=%q key_present=%t body_len=%d", read.Method, read.Path, read.Query,
			read.Header.Get("Idempotency-Key") != "", len(read.Body))
	}
}
