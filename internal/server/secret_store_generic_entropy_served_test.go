// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// A172-L4 Done-when: the generic high-entropy rule is a per-source opt-in.
// A Vault KV secret holds a GitLab token, a random-looking API secret no
// specific rule names, and a passphrase. A content-inspecting source without
// the opt-in reports the GitLab token only; with it, the run also reports the
// API secret as a masked, fingerprinted generic_high_entropy finding naming
// its field, and still nothing for the passphrase; a source asking for the
// generic rule without content inspection is refused before it is stored. No
// value reaches a finding or the event log.
func TestServedSecretStoreGenericHighEntropyRuleIsOptInA172L4(t *testing.T) {
	r := rand.New(rand.NewPCG(0xa172, 4)) // #nosec G404 -- a seeded fixture generator: reproducible test data, not a secret (CWE-338)
	const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	random := make([]byte, 40)
	for i := range random {
		random[i] = base62[r.IntN(len(base62))]
	}
	apiSecret := string(random)
	gitlab := a172Token("gl"+"pat-", "A172l4served", 26)
	var vaultSeen []string
	vault := a172VaultKVDouble(map[string]map[string]string{
		"ci/app": {"api_secret": apiSecret, "gitlab": gitlab, "note": "correct horse battery staple"},
	}, &vaultSeen)
	t.Cleanup(vault.Close)
	t.Setenv("TRSTCTL_A172L4_VAULT_TOKEN", "vault-token")
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A172L4_VAULT_TOKEN"))
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", string(authz.PrivateEgress))

	provider := func(inspect, generic bool) map[string]any {
		return map[string]any{"provider": "hashicorp-vault", "vault_url": vault.URL, "mount": "secret", "path_prefix": "ci",
			"token_ref":              "env:TRSTCTL_A172L4_VAULT_TOKEN", // #nosec G101 -- a credential reference to a fabricated fixture (CWE-798)
			"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, vault.URL)},
			"inspect_content": inspect, "generic_high_entropy": generic}
	}
	type finding struct {
		Kind     string `json:"kind"`
		Ref      string `json:"ref"`
		Metadata struct {
			Rule           string `json:"rule"`
			CredentialKind string `json:"credential_kind"`
			Field          string `json:"field"`
			Masked         string `json:"masked"`
		} `json:"metadata"`
		Fingerprint string `json:"fingerprint"`
	}
	run := func(name string, inspect, generic bool) map[string]finding {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
			"name": name, "kind": "secret_store", "config": map[string]any{"providers": []map[string]any{provider(inspect, generic)}}})
		var source struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
			t.Fatalf("create %s: %d %s", name, status, body)
		}
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
		var queued struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
			t.Fatalf("run %s: %d %s", name, status, body)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?limit=100&kind=secret_store_api_key&run_id="+queued.ID, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("findings %s: %d %s", name, status, body)
		}
		for _, value := range []string{apiSecret, gitlab, "correct horse battery staple"} {
			if strings.Contains(string(body), value) {
				t.Fatalf("a secret value reached the findings: %s", body)
			}
		}
		var list struct {
			Items []finding `json:"items"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatal(err)
		}
		out := map[string]finding{}
		for _, f := range list.Items {
			out[f.Metadata.Field+"/"+f.Metadata.Rule] = f
		}
		return out
	}

	off := run("a172l4-inspect", true, false)
	if len(off) != 1 || off["gitlab/gitlab_token"].Fingerprint == "" {
		t.Fatalf("content inspection without the opt-in = %+v; want the GitLab token only", off)
	}
	on := run("a172l4-generic", true, true)
	generic, ok := on["api_secret/generic_high_entropy"]
	if len(on) != 2 || on["gitlab/gitlab_token"].Fingerprint == "" || !ok || generic.Metadata.CredentialKind != "secret" ||
		generic.Metadata.Masked != "…(40 chars)" || generic.Fingerprint == "" || generic.Fingerprint == on["gitlab/gitlab_token"].Fingerprint {
		t.Fatalf("with the opt-in = %+v; want the GitLab token and a generic finding for api_secret", on)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "a172l4-generic-only", "kind": "secret_store", "config": map[string]any{"providers": []map[string]any{provider(false, true)}}})
	if status != http.StatusBadRequest || !strings.Contains(string(body), "generic_high_entropy needs inspect_content") {
		t.Fatalf("the generic rule without content inspection = %d %s; want 400 naming the reason", status, body)
	}
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		for _, value := range []string{apiSecret, gitlab} {
			if strings.Contains(string(e.Data), value) {
				t.Fatalf("event %s carries a secret value", e.Type)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
