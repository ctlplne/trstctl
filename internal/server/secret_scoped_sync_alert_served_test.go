// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

// refusingKVEmulator is the KV v2 double that refuses the writes and deletes
// a test names, as a destination whose policy forbids them would.
type refusingKVEmulator struct {
	*scopedKVEmulator
	server        *httptest.Server
	mu            sync.Mutex
	refuseWrite   map[string]bool
	refuseDelete  map[string]bool
	refusedWrites int
}

func newRefusingKVEmulator(t *testing.T, token string) *refusingKVEmulator {
	e := &refusingKVEmulator{
		scopedKVEmulator: &scopedKVEmulator{token: token, data: map[string]string{}, vers: map[string]int{}},
		refuseWrite:      map[string]bool{}, refuseDelete: map[string]bool{},
	}
	e.server = httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.server.Close)
	return e
}

func (e *refusingKVEmulator) serve(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	write := r.Method == http.MethodPost && e.refuseWrite[strings.TrimPrefix(r.URL.Path, "/v1/kv/data/apps/")]
	del := r.Method == http.MethodDelete && e.refuseDelete[strings.TrimPrefix(r.URL.Path, "/v1/kv/metadata/apps/")]
	if write {
		e.refusedWrites++
	}
	e.mu.Unlock()
	if write || del {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`, http.StatusForbidden)
		return
	}
	e.scopedKVEmulator.serve(w, r)
}

func (e *refusingKVEmulator) refuse(writes, deletes []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, key := range writes {
		e.refuseWrite[key] = true
	}
	for _, key := range deletes {
		e.refuseDelete[key] = true
	}
}

// A237-L4: a scoped sync's managed key the target does not take raises a
// warning on the notification surface, not only a status in `show`. A write
// of the key that fails for good and a delete of it that fails for good each
// raise one alert naming the definition, the destination key, the target and
// the closed reason, never a value; a replay and a rebuild from the log raise
// no second alert, and a key delivered fine raises none.
func TestServedScopedSyncDeliveryFailureAlertsA237L4(t *testing.T) {
	if store.SecretScopedSyncAlertDestination != notify.DestinationSecretSync {
		t.Fatalf("the store enqueues on %q, the notification surface names %q", store.SecretScopedSyncAlertDestination, notify.DestinationSecretSync)
	}
	const token = "a237l4-kv-token" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	emulator := newRefusingKVEmulator(t, token)
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
	registerServedTenant(t, h, "A237-L4 scoped sync alerts")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "a237l4-operator", "secrets:read", "secrets:write")
	request := func(method, path, key string, body any, want ...int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, key, body)
		for _, w := range want {
			if status == w {
				return raw
			}
		}
		t.Fatalf("%s %s: HTTP %d %s", method, path, status, raw)
		return nil
	}
	// Sync jobs wait for the projection checkpoint to pass their event; this
	// harness runs no live projector, so the test advances it.
	advance := func() {
		t.Helper()
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
	}
	drain := func() {
		t.Helper()
		for range 3 {
			advance()
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			_ = h.srv.Drain(ctx)
			cancel()
		}
	}
	// terminal gives each queued write and delete one attempt, so a refusal
	// fails for good, as a spent retry budget does.
	terminal := func() {
		t.Helper()
		for range 3 {
			advance()
			worker := orchestrator.NewOutbox(h.store, orchestrator.WithMaxAttempts(1))
			if _, err := worker.DispatchScoped(t.Context(), h.srv.obHandler, orchestrator.DestinationScope{
				IncludePrefixes: []string{secretSyncDestinationPrefix, store.SecretScopedSyncDeleteDestination},
			}); err != nil {
				t.Fatalf("terminal dispatch: %v", err)
			}
		}
	}
	type alertRow struct {
		Key   string
		Alert notify.Alert
	}
	alerts := func() []alertRow {
		t.Helper()
		rows, err := h.store.SystemPool().Query(t.Context(),
			`SELECT idempotency_key, payload FROM outbox WHERE tenant_id = $1 AND destination = $2 ORDER BY id`,
			h.tenant, notify.DestinationSecretSync)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []alertRow
		for rows.Next() {
			var row alertRow
			var payload []byte
			if err := rows.Scan(&row.Key, &payload); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(payload, &row.Alert); err != nil {
				t.Fatalf("alert payload %s: %v", payload, err)
			}
			for _, value := range []string{"a-one", "b-one", "c-one", token} {
				if strings.Contains(string(payload), value) {
					t.Fatalf("an alert carries a value (%q): %s", value, payload)
				}
			}
			out = append(out, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	request(http.MethodPost, "/api/v1/secrets/store", "a237l4-a", map[string]any{"name": "al237/prod/a", "value": "a-one"}, http.StatusCreated)
	request(http.MethodPost, "/api/v1/secrets/store", "a237l4-c", map[string]any{"name": "al237/prod/c", "value": "c-one"}, http.StatusCreated)
	var def struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(request(http.MethodPost, "/api/v1/secrets/scoped-syncs", "a237l4-define", map[string]any{
		"name": "al237-prod", "source_prefix": "al237/prod/", "target": "kv", "destination_prefix": "al237", "delete_scope": "managed",
	}, http.StatusCreated), &def); err != nil || def.ID == "" {
		t.Fatalf("define: %v", err)
	}
	base := "/api/v1/secrets/scoped-syncs/" + def.ID
	apply := func(key string) {
		t.Helper()
		var plan struct {
			PlanDigest string `json:"plan_digest"`
		}
		if err := json.Unmarshal(request(http.MethodPost, base+"/preview", "", nil, http.StatusOK), &plan); err != nil || plan.PlanDigest == "" {
			t.Fatalf("preview: %v", err)
		}
		request(http.MethodPost, base+"/apply", key, map[string]any{"plan_digest": plan.PlanDigest}, http.StatusOK, http.StatusCreated, http.StatusAccepted)
	}
	apply("a237l4-apply-1")
	drain()
	if v, _ := emulator.raw("al237/a"); v != "a-one" {
		t.Fatalf("destination a = %q", v)
	}
	if v, _ := emulator.raw("al237/c"); v != "c-one" {
		t.Fatalf("destination c = %q", v)
	}
	if got := alerts(); len(got) != 0 {
		t.Fatalf("delivered keys raised alerts: %+v", got)
	}

	// The target now refuses writing b and deleting c: b is a new source, and
	// c's source is gone, so the next plan writes b and deletes c.
	emulator.refuse([]string{"al237/b"}, []string{"al237/c"})
	request(http.MethodPost, "/api/v1/secrets/store", "a237l4-b", map[string]any{"name": "al237/prod/b", "value": "b-one"}, http.StatusCreated)
	request(http.MethodDelete, "/api/v1/secrets/store/al237/prod/c", "a237l4-delete-c", nil, http.StatusOK, http.StatusNoContent)
	apply("a237l4-apply-2")
	terminal()
	if emulator.refusedWrites == 0 {
		t.Fatal("the write of b never reached the target")
	}
	if v, ok := emulator.raw("al237/c"); !ok || v != "c-one" {
		t.Fatalf("destination c after a refused delete = %q %v", v, ok)
	}

	check := func(when string) {
		t.Helper()
		got := alerts()
		if len(got) != 2 {
			t.Fatalf("%s: alerts = %+v, want one for the failed write and one for the failed delete", when, got)
		}
		var write, del *alertRow
		for i := range got {
			switch {
			case strings.HasPrefix(got[i].Key, "secret.scoped_sync.delivery_failed:job:"):
				write = &got[i]
			case strings.HasPrefix(got[i].Key, "secret.scoped_sync.delivery_failed:delete:"):
				del = &got[i]
			}
		}
		if write == nil || del == nil {
			t.Fatalf("%s: alert keys %+v", when, got)
		}
		for _, a := range []*alertRow{write, del} {
			if a.Alert.Kind != notify.KindScopedSyncDeliveryFailed || a.Alert.Severity != notify.AlertSeverityWarning ||
				a.Alert.Subject != "al237-prod" || a.Alert.TenantID != h.tenant || a.Alert.OperationID != a.Key {
				t.Fatalf("%s: alert %+v", when, a.Alert)
			}
		}
		if d := write.Alert.Detail; !strings.Contains(d, "could not write al237/b to target kv") {
			t.Fatalf("%s: write alert detail %q", when, d)
		}
		if d := del.Alert.Detail; !strings.Contains(d, "could not delete al237/c from target kv") ||
			!strings.Contains(d, "exhausted its retry budget") || !strings.Contains(d, "next plan proposes deleting it again") {
			t.Fatalf("%s: delete alert detail %q", when, d)
		}
		if m := notify.FormatMessage(write.Alert); !strings.HasPrefix(m, "A scoped secret sync could not deliver a key: al237-prod") {
			t.Fatalf("%s: message %q", when, m)
		}
		t.Logf("%s: write alert %q; delete alert %q", when, write.Alert.Detail, del.Alert.Detail)
	}
	check("after the failures")

	// The console's notification inbox lists both, as it reads them.
	inboxTok := seedScopedTokenSubject(t, h.store, h.tenant, "a237l4-watcher", "notifications:read")
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/notifications?limit=50", inboxTok, nil)
	var inbox struct {
		Items []struct {
			Destination string `json:"destination"`
			Kind        string `json:"kind"`
			Subject     string `json:"subject"`
			Severity    string `json:"severity"`
			Detail      string `json:"detail"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &inbox) != nil {
		t.Fatalf("notification inbox: HTTP %d %s", status, raw)
	}
	listed := 0
	for _, item := range inbox.Items {
		if item.Kind == notify.KindScopedSyncDeliveryFailed && item.Destination == notify.DestinationSecretSync &&
			item.Subject == "al237-prod" && item.Severity == notify.AlertSeverityWarning && strings.Contains(item.Detail, "al237/") {
			listed++
		}
	}
	if listed != 2 {
		t.Fatalf("the inbox lists %d scoped sync alerts, want 2: %s", listed, raw)
	}

	// The failures stay visible in show, as before.
	var view struct {
		Keys []struct {
			Key       string `json:"key"`
			JobStatus string `json:"job_status"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(request(http.MethodGet, base, "", nil, http.StatusOK), &view); err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{}
	for _, k := range view.Keys {
		statuses[k.Key] = k.JobStatus
	}
	if statuses["al237/b"] != string(store.SecretSyncJobFailed) {
		t.Fatalf("show reads %+v, want b's job failed", statuses)
	}

	// Delivering again and rebuilding from the log raise no second alert.
	terminal()
	drain()
	if err := projections.New(h.store).Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	check("after a replay and a rebuild")
}
