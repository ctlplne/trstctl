// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
)

// A237-L7 Done-when: a scoped sync can set its own drift-check interval. Two
// auto syncs write to a destination that reads back: one keeps the 15-minute
// default, the other sets 1h. After both destinations are changed outside the
// syncs, a pass 16 minutes later restores the default sync's key and leaves
// the hourly one drifted; a pass 61 minutes later restores it too. The view
// names the interval; an interval under a minute, over a day or not a duration
// is refused, and a replacement that leaves it out keeps it.
func TestServedScopedSyncDriftIntervalPerDefinitionA237L7(t *testing.T) {
	const token = "a237l7-kv-kv-kv-kv" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
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
	registerServedTenant(t, h, "A237-L7 drift interval")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "a237l7-operator", "secrets:read", "secrets:write")
	call := func(method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	call(http.MethodPost, "/api/v1/secrets/store", "a237l7-fast", map[string]any{"name": "iv237/fast/a", "value": "fast-one"}, http.StatusCreated)
	call(http.MethodPost, "/api/v1/secrets/store", "a237l7-slow", map[string]any{"name": "iv237/slow/a", "value": "slow-one"}, http.StatusCreated)

	for _, bad := range []string{"30s", "25h", "every hour"} {
		raw := call(http.MethodPost, "/api/v1/secrets/scoped-syncs", "a237l7-bad-"+bad, map[string]any{
			"name": "iv237-bad", "source_prefix": "iv237/fast/", "target": "kv", "destination_prefix": "iv237bad", "reconcile_interval": bad,
		}, http.StatusBadRequest)
		if !strings.Contains(string(raw), "reconcile_interval") {
			t.Fatalf("interval %q refused without naming it: %s", bad, raw)
		}
	}
	define := func(name, source, dest, interval string) string {
		t.Helper()
		body := map[string]any{"name": name, "source_prefix": source, "target": "kv", "destination_prefix": dest, "mode": "auto"}
		if interval != "" {
			body["reconcile_interval"] = interval
		}
		var def struct {
			ID                string `json:"id"`
			ReconcileInterval string `json:"reconcile_interval"`
		}
		if err := json.Unmarshal(call(http.MethodPost, "/api/v1/secrets/scoped-syncs", "a237l7-define-"+name, body, http.StatusCreated), &def); err != nil || def.ID == "" {
			t.Fatalf("define %s: %v", name, err)
		}
		if interval != "" && def.ReconcileInterval != "1h0m0s" {
			t.Fatalf("the view names the interval %q, want 1h0m0s", def.ReconcileInterval)
		}
		// Served tests share a tenant: leave no automatic sync for a later
		// test's reconcile pass to pick up.
		t.Cleanup(func() {
			if status, raw := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/scoped-syncs/"+def.ID+"/mode", tok,
				"a237l7-manual-"+name, map[string]any{"mode": "manual"}); status != http.StatusOK {
				t.Errorf("set %s manual: HTTP %d %s", name, status, raw)
			}
		})
		return def.ID
	}
	define("iv237-fast", "iv237/fast/", "iv237fast", "")
	slow := define("iv237-slow", "iv237/slow/", "iv237slow", "1h")

	state := api.ScopedSyncReconcileState{}
	start := time.Now().UTC()
	pass := func(at time.Duration) {
		t.Helper()
		if _, err := h.srv.api.ReconcileScopedSecretSyncs(t.Context(), []string{h.tenant}, state, start.Add(at), 15*time.Minute); err != nil {
			t.Fatalf("reconcile at +%s: %v", at, err)
		}
		drainServedOutbox(t, h)
	}
	pass(0)
	for key, want := range map[string]string{"iv237fast/a": "fast-one", "iv237slow/a": "slow-one"} {
		if v, _ := emulator.raw(key); v != want {
			t.Fatalf("after the first pass %s = %q, want %q", key, v, want)
		}
	}
	emulator.mu.Lock()
	emulator.data["iv237fast/a"], emulator.data["iv237slow/a"] = "changed-outside", "changed-outside"
	emulator.vers["iv237fast/a"]++
	emulator.vers["iv237slow/a"]++
	emulator.mu.Unlock()

	pass(16 * time.Minute)
	if v, _ := emulator.raw("iv237fast/a"); v != "fast-one" {
		t.Fatalf("the default sync's key after 16 minutes = %q, want restored", v)
	}
	if v, _ := emulator.raw("iv237slow/a"); v != "changed-outside" {
		t.Fatalf("the hourly sync re-planned before its hour: %q", v)
	}
	pass(61 * time.Minute)
	if v, _ := emulator.raw("iv237slow/a"); v != "slow-one" {
		t.Fatalf("the hourly sync's key after 61 minutes = %q, want restored", v)
	}

	// A replacement that leaves the interval out keeps it.
	var replaced struct {
		ReconcileInterval string `json:"reconcile_interval"`
	}
	if err := json.Unmarshal(call(http.MethodPut, "/api/v1/secrets/scoped-syncs/"+slow, "a237l7-replace", map[string]any{
		"name": "iv237-slow", "source_prefix": "iv237/slow/", "target": "kv", "destination_prefix": "iv237slow", "delete_scope": "managed",
	}, http.StatusOK), &replaced); err != nil || replaced.ReconcileInterval != "1h0m0s" {
		t.Fatalf("a replacement without an interval reads %q (%v), want 1h0m0s kept", replaced.ReconcileInterval, err)
	}
}
