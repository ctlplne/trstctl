// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// CR-049: Go's JSON struct decoder accepts case-folded field names. The API
// must not store raw keys that its authorization checks do not recognize but
// the discovery worker later treats as a credential or private-egress grant.
func TestCR049DiscoverySourceRejectsMisCasedCredentialAndEgressKeys(t *testing.T) {
	const envName = "TRSTCTL_CR049_CANARY"
	canary := "canary-value-for-" + envName
	t.Setenv(envName, canary)

	var mu sync.Mutex
	var seen []string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("X-Vault-Token"))
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer collector.Close()
	loopback := serviceNowSinkCIDR(t, collector.URL)
	h := newOperatingServedHarness(t, config.Protocols{}) // no approved env references
	var mcpPerms []string
	for _, p := range authz.BuiltinRoles()["mcp"].Permissions {
		mcpPerms = append(mcpPerms, string(p))
	}
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "cr049-mcp-automation", mcpPerms...)
	create := func(id, name string, provider map[string]any) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, id, map[string]any{
			"kind": "cloud_secret", "name": name, "config": map[string]any{"providers": []any{provider}},
		})
	}
	if code, body := create("cr049-canonical-ref", "CR049 canonical env ref", map[string]any{
		"provider": "hashicorp-vault", "vault_url": "https://vault.example.com", "token_ref": "env:" + envName, "mount": "secret",
	}); code != http.StatusBadRequest {
		t.Fatalf("canonical unapproved env ref = HTTP %d %s; want 400", code, body)
	}
	if code, body := create("cr049-canonical-egress", "CR049 canonical private egress", map[string]any{
		"provider": "hashicorp-vault", "vault_url": collector.URL, "allow_private_endpoint": true,
		"private_egress_cidrs": []string{loopback}, "mount": "secret",
	}); code != http.StatusForbidden {
		t.Fatalf("canonical private egress without grant = HTTP %d %s; want 403", code, body)
	}
	code, body := create("cr049-miscased", "CR049 mis-cased bypass", map[string]any{
		"provider": "hashicorp-vault", "vault_url": collector.URL, "mount": "secret",
		"Token_Ref": "env:" + envName, "Allow_Private_Endpoint": true,
		"Private_Egress_CIDRs": []string{loopback},
	})
	if code != http.StatusBadRequest {
		t.Errorf("mis-cased credential and egress keys = HTTP %d %s; want 400", code, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if code != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		return
	}
	code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, "cr049-run", map[string]any{"source_id": source.ID})
	var run struct {
		ID string `json:"id"`
	}
	if code != http.StatusCreated || json.Unmarshal(body, &run) != nil || run.ID == "" {
		t.Fatalf("queue mis-cased discovery run = HTTP %d %s", code, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, token := range seen {
		if strings.TrimSpace(token) == canary {
			t.Fatal("private collector received an unapproved process environment value as X-Vault-Token")
		}
	}
}

// CR-061 is the private-egress half of the same JSON case-folding flaw. Keep
// this separate from CR-049's combined credential test so one guard cannot
// accidentally hide a regression in the other.
func TestCR061DiscoverySourceRejectsCaseVariantPrivateEgressGrant(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer collector.Close()
	loopback := serviceNowSinkCIDR(t, collector.URL)
	h := newOperatingServedHarness(t, config.Protocols{})
	var mcpPerms []string
	for _, p := range authz.BuiltinRoles()["mcp"].Permissions {
		mcpPerms = append(mcpPerms, string(p))
	}
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "cr061-mcp-automation", mcpPerms...)
	create := func(key, name string) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, key, map[string]any{
			"kind": "cloud_secret", "name": name, "config": map[string]any{"providers": []any{map[string]any{
				"provider": "hashicorp-vault", "vault_url": collector.URL, "mount": "secret",
				key: true, "private_egress_cidrs": []string{loopback},
			}}},
		})
	}
	if code, body := create("allow_private_endpoint", "CR061 canonical private egress"); code != http.StatusForbidden {
		t.Fatalf("canonical private egress without egress:private = HTTP %d %s; want 403", code, body)
	}
	if code, body := create("Allow_Private_Endpoint", "CR061 case-variant private egress"); code != http.StatusBadRequest {
		t.Fatalf("case-variant private egress control = HTTP %d %s; want 400 before storage", code, body)
	}
}
