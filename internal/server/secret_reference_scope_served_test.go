// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// TestServedSecretReferencesIntoRestrictedEnvironmentsNeedAGrantA235L2 is
// A235-L2 over the served API. A caller holding an integration's permission
// but not granted a restricted environment cannot set up a secret://
// reference into it on any surface trstctl later redeems by name with no
// request principal — a relay schedule's token, a connector target's
// credential, an inline endpoint destination, a discovery source's bind
// password, a notification channel's or an observer's credential, a DNS-01
// provider's credentials, an MDM SCEP challenge key, a secret sync's workload
// proof — whichever spelling the reference takes, and the refusal is the same
// whether or not the secret exists. A member of the environment sets the same
// reference up, and a reference into an open environment needs no grant. A
// leaked-secret move naming a restricted secret answers as for a missing one.
func TestServedSecretReferencesIntoRestrictedEnvironmentsNeedAGrantA235L2(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "A235-L2 secret references tenant")
	perms := []string{"secrets:read", "secrets:write", "certs:write", "certs:issue", "connectors:write", "connectors:read",
		"notifications:write", "issuers:write", "issuers:read", "discovery:write", "discovery:read"}
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a235l2-admin", append([]string{"access:write"}, perms...)...)
	outsider := seedScopedTokenSubject(t, h.store, h.tenant, "a235l2-outsider", perms...)
	member := seedScopedTokenSubject(t, h.store, h.tenant, "a235l2-member", perms...)

	call := func(tok, method, path string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReq(t, h, method, path, tok, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	call(admin, http.MethodPost, "/api/v1/secrets/projects", map[string]any{"slug": "vault235", "environments": []any{
		map[string]any{"slug": "dev"}, map[string]any{"slug": "prod", "restricted": true},
	}}, http.StatusCreated)
	call(admin, http.MethodPut, "/api/v1/secrets/projects/vault235/members/a235l2-member",
		map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	call(member, http.MethodPost, "/api/v1/secrets/store", map[string]any{"name": "vault235/prod/token", "value": "prod-token-a235l2"}, http.StatusCreated)
	call(admin, http.MethodPost, "/api/v1/secrets/store", map[string]any{"name": "vault235/dev/token", "value": "dev-token-a235l2"}, http.StatusCreated)

	const refusal = "names a secret in a restricted environment you are not granted"
	// Every spelling a redeemer resolves to vault235/prod/..., and a name
	// there that does not exist: the refusal is the same.
	prodRefs := []string{
		"secret://vault235/prod/token", "secret:///vault235/prod/token/", "secret://vault235/prod/token?version=1",
		"secret://vault235/prod%2Ftoken", "secret://vault235/prod/%74oken", " secret://vault235/prod/token ",
		"secret://vault235/prod/no-such-secret",
	}
	relayAgent := uuid.NewString()
	surfaces := []struct {
		name, method, path string
		body               func(ref string) any
	}{
		{"ticket intake token", http.MethodPut, "/api/v1/issuance-requests/intake-schedule", func(ref string) any {
			return map[string]any{"system": "servicenow", "name": "a235l2", "instance_url": "https://sn.example.test",
				"token_ref": ref, "sn_table": "incident", "subject_field": "u_subject", "profile_field": "u_profile",
				"requester_field": "requested_by", "interval_seconds": 3600}
		}},
		{"MDM poll token", http.MethodPut, "/api/v1/mdm/poll-schedule", func(ref string) any {
			return map[string]any{"mdm": "intune", "base_url": "https://graph.example.test", "token_ref": ref, "interval_seconds": 3600}
		}},
		{"connector target credential", http.MethodPost, "/api/v1/connectors/targets", func(ref string) any {
			return map[string]any{"name": "a235l2-kemp", "connector": "kemp",
				"config": map[string]any{"endpoint": "https://kemp.example.test", "token_ref": ref}}
		}},
		{"inline endpoint destination", http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", func(ref string) any {
			return map[string]any{"owner_id": uuid.NewString(), "identity_name": "a235l2.example.test", "reason": "A235-L2",
				"issuer": map[string]any{"source": "external", "id": "a235l2-ca"},
				"target": map[string]any{"name": "a235l2-inline", "connector": "kemp",
					"config": map[string]any{"endpoint": "https://kemp.example.test", "token_ref": ref}}}
		}},
		{"discovery bind password", http.MethodPost, "/api/v1/discovery/sources", func(ref string) any {
			return map[string]any{"name": "a235l2-adcs", "kind": "adcs", "config": map[string]any{
				"url": "ldaps://dc.example", "configuration_dn": "CN=Configuration,DC=example", "bind_dn": "CN=reader,DC=example",
				"password_ref": ref, "relay_agent_id": relayAgent}}
		}},
		{"notification channel credential", http.MethodPost, "/api/v1/notification-channels", func(ref string) any {
			return map[string]any{"id": "pagerduty", "channel_type": "pagerduty", "label": "A235-L2 pager",
				"endpoint_url": "https://notifications.example.test/pagerduty", "credential_ref": ref, "enabled": true}
		}},
		{"observer credential", http.MethodPost, "/api/v1/observers", func(ref string) any {
			return map[string]any{"name": "a235l2-observer", "events_url": "https://observer.example.test/events", "credential_ref": ref}
		}},
		{"DNS-01 credentials", http.MethodPost, "/api/v1/acme/dns-01/provider-configs", func(ref string) any {
			return map[string]any{"name": "a235l2-dns", "provider": "cloudflare", "zone": "a235l2.test",
				"credential_refs": map[string]any{"api_token_ref": ref}, "config": map[string]any{"zone_id": "zone-a235l2"},
				"caa_issuer_domain": "trstctl.example", "allowed_methods": []string{"dns-01"}}
		}},
		{"MDM SCEP challenge key", http.MethodPost, "/api/v1/mdm/scep/policies", func(ref string) any {
			return map[string]any{"name": "a235l2-scep", "provider": "jamf", "scep_profile": "mac-scep",
				"scep_endpoint": h.ts.URL + "/scep/pkiclient.exe", "challenge_mode": "hmac-dynamic",
				"challenge_credential_ref": ref, "enabled": true}
		}},
		{"secret sync workload proof", http.MethodPost, "/api/v1/secrets/syncs/workload-identity-sources", func(ref string) any {
			return map[string]any{"name": "a235l2 federation", "provider": "aws", "role_arn": "arn:aws:iam::123456789012:role/a235l2",
				"audience": "trstctl", "subject": "system:serviceaccount:a235l2:sync", "target_id": "a235l2-target",
				"workload_proof_ref": ref, "trust_source_id": uuid.NewString()}
		}},
	}
	refused := func(tok string, s struct {
		name, method, path string
		body               func(ref string) any
	}, ref string) (bool, int, string) {
		t.Helper()
		status, raw := secretsReq(t, h, s.method, s.path, tok, s.body(ref))
		return status == http.StatusForbidden && strings.Contains(string(raw), refusal), status, string(raw)
	}
	for _, s := range surfaces {
		for _, ref := range prodRefs {
			if ok, status, raw := refused(outsider, s, ref); !ok {
				t.Fatalf("%s: a non-member set up %q: HTTP %d %s", s.name, ref, status, raw)
			}
		}
		if ok, status, raw := refused(member, s, "secret://vault235/prod/token"); ok {
			t.Fatalf("%s: prod's member was refused its own environment's secret: HTTP %d %s", s.name, status, raw)
		}
		if ok, status, raw := refused(outsider, s, "secret://vault235/dev/token"); ok {
			t.Fatalf("%s: a reference into the open environment was refused: HTTP %d %s", s.name, status, raw)
		}
	}

	// A member's channel and target are set up in full; the outsider then
	// cannot repoint either while it keeps the prod reference.
	call(member, http.MethodPost, "/api/v1/notification-channels", map[string]any{"id": "webhook", "channel_type": "webhook", // #nosec G101 -- a secret:// reference or secret name in a test fixture, not a credential value (CWE-798)
		"label": "A235-L2 webhook", "endpoint_url": "https://notifications.example.test/webhook",
		"credential_ref": "secret://vault235/prod/token", "enabled": true}, http.StatusCreated)
	if ok, status, raw := refused(outsider, struct {
		name, method, path string
		body               func(ref string) any
	}{"channel repoint", http.MethodPut, "/api/v1/notification-channels/webhook", func(ref string) any {
		return map[string]any{"channel_type": "webhook", "label": "A235-L2 webhook", "endpoint_url": "https://attacker.example.test/hook",
			"credential_ref": ref, "enabled": true}
	}}, "secret://vault235/prod/token"); !ok {
		t.Fatalf("a non-member repointed a channel that keeps a prod reference: HTTP %d %s", status, raw)
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call(member, http.MethodPost, "/api/v1/connectors/targets", map[string]any{"name": "a235l2-kemp-prod",
		"connector": "kemp", "config": map[string]any{"endpoint": "https://kemp.example.test", "token_ref": "secret://vault235/prod/token"}}, // #nosec G101 -- a secret:// reference or secret name in a test fixture, not a credential value (CWE-798)
		http.StatusCreated), &target); err != nil || target.ID == "" {
		t.Fatalf("the member's target: %v", err)
	}
	if ok, status, raw := refused(outsider, struct {
		name, method, path string
		body               func(ref string) any
	}{"target repoint", http.MethodPut, "/api/v1/connectors/targets/" + target.ID, func(ref string) any {
		return map[string]any{"name": "a235l2-kemp-prod", "connector": "kemp",
			"config": map[string]any{"endpoint": "https://attacker.example.test", "token_ref": ref}}
	}}, "secret://vault235/prod/token"); !ok {
		t.Fatalf("a non-member repointed a target that keeps a prod reference: HTTP %d %s", status, raw)
	}

	// A leaked-secret move naming a restricted secret answers as for a
	// missing one; the member's move is checked on its merits.
	leakID := seedA235L2LeakedSecretFinding(t, h)
	missing := call(outsider, http.MethodPost, "/api/v1/discovery/findings/"+leakID+"/secret-move",
		map[string]any{"secret_name": "vault235/prod/no-such-secret", "secret_version": 1}, http.StatusConflict) // #nosec G101 -- a secret:// reference or secret name in a test fixture, not a credential value (CWE-798)
	restricted := call(outsider, http.MethodPost, "/api/v1/discovery/findings/"+leakID+"/secret-move",
		map[string]any{"secret_name": "vault235/prod/token", "secret_version": 1}, http.StatusConflict)
	if string(missing) != string(restricted) {
		t.Fatalf("a restricted secret's move answers %s, a missing one %s", restricted, missing)
	}
	call(member, http.MethodPost, "/api/v1/discovery/findings/"+leakID+"/secret-move",
		map[string]any{"secret_name": "vault235/prod/token", "secret_version": 1}, http.StatusOK)
	t.Log("A235L2_SECRET_REFERENCES_OK surfaces=10 spellings=7")
}

// seedA235L2LeakedSecretFinding records one leaked-secret finding.
func seedA235L2LeakedSecretFinding(t *testing.T, h *servedHarness) string {
	t.Helper()
	ctx := context.Background()
	sourceID, runID := uuid.NewString(), uuid.NewString()
	now := time.Now().UTC()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := h.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: h.tenant, Kind: "manual", Name: "a235l2-scan",
			Config: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		return h.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: h.tenant, SourceID: sourceID, Status: "running", CreatedAt: now,
		})
	}); err != nil {
		t.Fatalf("seed the scan: %v", err)
	}
	finding, err := h.srv.orch.RecordDiscoveryFinding(ctx, h.tenant, store.DiscoveryFinding{
		RunID: runID, SourceID: sourceID, Kind: "leaked_secret", Ref: "repo/app.env:3",
		Provenance: "manual:a235l2", Fingerprint: "a235l2-leak", RiskScore: 80,
		Metadata: json.RawMessage(`{"rule_id":"generic-api-key","file":"app.env","line":3}`),
	})
	if err != nil {
		t.Fatalf("record the leaked secret: %v", err)
	}
	return finding.ID
}
