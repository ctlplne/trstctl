// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"
)

// F259: with protocols.ssh_user_principals set, a direct user certificate may
// name only listed logins, matched exactly, on the raw route, the product
// preview and the product issue route.
func TestServedSSHUserPrincipalAllowlist(t *testing.T) {
	protocols := sshServedProtocols()
	protocols.SSHUserPrincipals = []string{"deploy", "oncall"}
	h := newOperatingServedHarness(t, protocols)
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ssh-issuer", []string{"certs:issue"})
	pub := sshTestPublicKey(t)
	raw := func(keyID string, principals ...string) map[string]any {
		return map[string]any{"public_key": pub, "key_id": keyID, "principals": principals, "ttl_seconds": 600}
	}
	product := func(keyID string, principals ...string) map[string]any {
		return map[string]any{"certificate_type": "user", "public_key": pub, "key_id": keyID, "principals": principals, "ttl_seconds": 600}
	}
	if code, body := sshPost(t, h.ts, "/ssh/issue/user", token, "allow-listed", raw("listed", "deploy", "oncall")); code != http.StatusOK {
		t.Fatalf("listed principals over the raw route = %d %s, want 200", code, body)
	}
	if code, body := sshPost(t, h.ts, "/api/v1/ssh/certificates", token, "allow-listed-product", product("listed-product", "deploy")); code != http.StatusCreated {
		t.Fatalf("listed principal over the product route = %d %s, want 201", code, body)
	}
	for _, c := range []struct {
		name, path, idem string
		body             map[string]any
		principal        string
	}{
		{"raw root", "/ssh/issue/user", "deny-root", raw("root", "deploy", "root"), "root"},
		{"raw case", "/ssh/issue/user", "deny-case", raw("case", "Deploy"), "Deploy"},
		{"product preview root", "/api/v1/ssh/certificates/preview", "", product("preview-root", "root"), "root"},
		{"product issue root", "/api/v1/ssh/certificates", "deny-root-product", product("product-root", "root"), "root"},
	} {
		code, body := sshPost(t, h.ts, c.path, token, c.idem, c.body)
		if code != http.StatusForbidden || !strings.Contains(body, c.principal) {
			t.Errorf("%s = %d %s, want 403 naming %q", c.name, code, body, c.principal)
		}
	}
}
