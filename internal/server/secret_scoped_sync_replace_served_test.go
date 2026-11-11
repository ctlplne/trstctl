// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
)

// TestServedScopedSyncDefinitionIsReplacedInPlaceA237L3 is A237-L3 over the
// served API and the CLI. A definition is replaced under the same ID:
//   - a replacement that keeps the destination keeps the keys it manages;
//   - one that moves the destination releases them (they stay at the old
//     place) and the next plan writes the new place;
//   - another definition's name is a conflict, an unknown ID 404;
//   - the same definition again records nothing;
//   - an approved definition stays approved when the mode is left out, and
//     only access:write takes it out of approval-gated convergence.
func TestServedScopedSyncDefinitionIsReplacedInPlaceA237L3(t *testing.T) {
	const token = "a237l3-kv-token" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	emulator := newScopedKVEmulator(t, token)
	pusher, err := secretsync.NewVaultKVV2Pusher(secretsync.VaultKVV2Config{
		Endpoint: emulator.server.URL, HTTPClient: emulator.server.Client(), Token: []byte(token), Mount: "kv", PathPrefix: "apps",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pusher.Close)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = SecretSyncTargetRegistry{servedTestTenant: {"kv": secretsync.NewTarget("kv", pusher)}}
	})
	registerServedTenant(t, h, "A237-L3 scoped sync replace tenant")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a237l3-admin", "access:write", "secrets:read", "secrets:write")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "a237l3-operator", "secrets:read", "secrets:write")
	call := func(token, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, token, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	type keyView struct {
		Key string `json:"key"`
	}
	type view struct {
		ID                string    `json:"id"`
		Name              string    `json:"name"`
		DestinationPrefix string    `json:"destination_prefix"`
		DeleteScope       string    `json:"delete_scope"`
		Mode              string    `json:"mode"`
		Keys              []keyView `json:"keys"`
	}
	decode := func(raw []byte) view {
		t.Helper()
		var v view
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	keys := func(v view) []string {
		var out []string
		for _, k := range v.Keys {
			out = append(out, k.Key)
		}
		return out
	}
	call(tok, http.MethodPost, "/api/v1/secrets/store", "a237l3-a", map[string]any{"name": "rep237/prod/a", "value": "a-one"}, http.StatusCreated)
	defined := decode(call(tok, http.MethodPost, "/api/v1/secrets/scoped-syncs", "a237l3-define", map[string]any{
		"name": "rep237", "source_prefix": "rep237/prod/", "target": "kv", "destination_prefix": "rep", "delete_scope": "managed",
	}, http.StatusCreated))
	sync := "/api/v1/secrets/scoped-syncs/" + defined.ID
	drain := func() {
		t.Helper()
		for range 3 {
			head, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.store.SystemPool().Exec(t.Context(),
				`UPDATE projection_checkpoint SET applied_seq = GREATEST(applied_seq, $1), updated_at = now() WHERE id = 1`, head); err != nil {
				t.Fatal(err)
			}
			if _, err := h.store.SystemPool().Exec(t.Context(),
				`UPDATE outbox SET next_attempt_at = now() - interval '1 second' WHERE tenant_id = $1 AND status = 'pending'`, h.tenant); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			_ = h.srv.Drain(ctx)
			cancel()
		}
	}
	applyPlan := func(key string) {
		t.Helper()
		var plan struct {
			PlanDigest string `json:"plan_digest"`
		}
		if err := json.Unmarshal(call(tok, http.MethodPost, sync+"/preview", "", nil, http.StatusOK), &plan); err != nil {
			t.Fatal(err)
		}
		call(tok, http.MethodPost, sync+"/apply", key, map[string]any{"plan_digest": plan.PlanDigest}, http.StatusCreated)
		drain()
	}
	applyPlan("a237l3-apply-1")
	if got := keys(decode(call(tok, http.MethodGet, sync, "", nil, http.StatusOK))); !slices.Equal(got, []string{"rep/a"}) {
		t.Fatalf("managed keys after the first apply = %v", got)
	}
	replaced := func() int { return servedEventCount(t, h, "secret.scoped_sync.replaced") }

	// The same destination keeps the keys managed.
	same := decode(call(tok, http.MethodPut, sync, "a237l3-replace-scope", map[string]any{
		"name": "rep237", "source_prefix": "rep237/prod/", "target": "kv", "destination_prefix": "rep", "delete_scope": "none",
	}, http.StatusOK))
	if same.ID != defined.ID || same.DeleteScope != "none" || !slices.Equal(keys(same), []string{"rep/a"}) {
		t.Fatalf("a replacement keeping the destination = %+v", same)
	}

	// The CLI moves the destination: the keys are released and stay.
	dir := t.TempDir()
	body := filepath.Join(dir, "replace.json")
	if err := os.WriteFile(body, []byte(`{"name":"rep237","source_prefix":"rep237/prod/","target":"kv","destination_prefix":"rep2","delete_scope":"managed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Run(t.Context(), []string{"--server", h.ts.URL, "--token", tok, "--tenant", h.tenant,
		"secrets", "scoped-syncs", "replace", defined.ID, "-f", body}, cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("trstctl secrets scoped-syncs replace: %s%s", stdout.String(), stderr.String())
	}
	moved := decode(call(tok, http.MethodGet, sync, "", nil, http.StatusOK))
	if moved.DestinationPrefix != "rep2" || len(moved.Keys) != 0 {
		t.Fatalf("after moving the destination = %+v", moved)
	}
	if v, ok := emulator.raw("rep/a"); !ok || v != "a-one" {
		t.Fatalf("the released key at the old destination = %q, %v", v, ok)
	}
	applyPlan("a237l3-apply-2")
	if got := keys(decode(call(tok, http.MethodGet, sync, "", nil, http.StatusOK))); !slices.Equal(got, []string{"rep2/a"}) {
		t.Fatalf("managed keys after applying the moved definition = %v", got)
	}

	// Conflicts, unknown IDs, and a replacement that changes nothing.
	call(tok, http.MethodPost, "/api/v1/secrets/scoped-syncs", "a237l3-other", map[string]any{
		"name": "other237", "source_prefix": "rep237/prod/", "target": "kv", "destination_prefix": "other",
	}, http.StatusCreated)
	call(tok, http.MethodPut, sync, "a237l3-taken", map[string]any{
		"name": "other237", "source_prefix": "rep237/prod/", "target": "kv", "destination_prefix": "rep2", "delete_scope": "managed",
	}, http.StatusConflict)
	call(tok, http.MethodPut, "/api/v1/secrets/scoped-syncs/00000000-0000-4000-8000-000000000237", "a237l3-missing", map[string]any{
		"name": "rep237", "source_prefix": "rep237/prod/", "target": "kv",
	}, http.StatusNotFound)
	before := replaced()
	call(tok, http.MethodPut, sync, "a237l3-unchanged", map[string]any{
		"name": "rep237", "source_prefix": "rep237/prod/", "target": "kv", "destination_prefix": "rep2", "delete_scope": "managed",
	}, http.StatusOK)
	if after := replaced(); after != before || before != 2 {
		t.Fatalf("replaced events = %d then %d, want 2 and none for an unchanged definition", before, after)
	}

	// An approved definition stays approved; only access:write lifts the gate.
	call(tok, http.MethodPut, sync+"/mode", "a237l3-approved", map[string]any{"mode": "approved"}, http.StatusOK)
	if v := decode(call(tok, http.MethodPut, sync, "a237l3-keep-gate", map[string]any{
		"name": "rep237", "source_prefix": "rep237/prod/", "target": "kv", "destination_prefix": "rep3", "delete_scope": "managed",
	}, http.StatusOK)); v.Mode != "approved" {
		t.Fatalf("a replacement without a mode left the gate: %+v", v)
	}
	call(tok, http.MethodPut, sync, "a237l3-lift", map[string]any{
		"name": "rep237", "source_prefix": "rep237/prod/", "target": "kv", "destination_prefix": "rep3", "delete_scope": "managed", "mode": "auto",
	}, http.StatusForbidden)
	if v := decode(call(admin, http.MethodPut, sync, "a237l3-lift-admin", map[string]any{
		"name": "rep237", "source_prefix": "rep237/prod/", "target": "kv", "destination_prefix": "rep3", "delete_scope": "managed", "mode": "auto",
	}, http.StatusOK)); v.Mode != "auto" {
		t.Fatalf("the administrator's replacement = %+v", v)
	}
	t.Log("A237L3_REPLACE_OK")
}
