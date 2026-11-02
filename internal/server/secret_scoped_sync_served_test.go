// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

// kvProbe reads a KV v2 destination the way an operator would check it.
type kvProbe interface {
	value(t *testing.T, path string) (string, bool)
	versions(t *testing.T, path string) int
	seed(t *testing.T, path, value string)
}

// scopedKVEmulator is a KV v2 HTTP double: data read and check-and-set write,
// metadata list and delete, and a version count per path.
type scopedKVEmulator struct {
	server *httptest.Server
	token  string
	mu     sync.Mutex
	data   map[string]string
	vers   map[string]int
}

func newScopedKVEmulator(t *testing.T, token string) *scopedKVEmulator {
	e := &scopedKVEmulator{token: token, data: map[string]string{}, vers: map[string]int{}}
	e.server = httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.server.Close)
	return e
}

func (e *scopedKVEmulator) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != e.token {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if dir, ok := strings.CutPrefix(r.URL.Path, "/v1/kv/metadata/apps"); ok {
		dir = strings.TrimPrefix(dir, "/")
		if r.Method == http.MethodDelete {
			delete(e.data, dir)
			delete(e.vers, dir)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		seen, keys := map[string]bool{}, []string{}
		for path := range e.data {
			rel := path
			if dir != "" {
				if rel, ok = strings.CutPrefix(path, dir+"/"); !ok {
					continue
				}
			}
			entry := rel
			if head, _, nested := strings.Cut(rel, "/"); nested {
				entry = head + "/"
			}
			if !seen[entry] {
				seen[entry] = true
				keys = append(keys, entry)
			}
		}
		if len(keys) == 0 {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/v1/kv/data/apps/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		value, found := e.data[path]
		if !found {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"data": map[string]string{"value": value}, "metadata": map[string]int{"version": e.vers[path]},
		}})
	case http.MethodPost:
		var req struct {
			Options struct {
				CAS int `json:"cas"`
			} `json:"options"`
			Data map[string]string `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Options.CAS != e.vers[path] {
			http.Error(w, `{"errors":["check-and-set parameter did not match"]}`, http.StatusBadRequest)
			return
		}
		e.data[path] = req.Data["value"]
		e.vers[path]++
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]int{"version": e.vers[path]}})
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func (e *scopedKVEmulator) value(_ *testing.T, path string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.data["inv237/"+path]
	return v, ok
}

func (e *scopedKVEmulator) versions(_ *testing.T, path string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.vers["inv237/"+path]
}

func (e *scopedKVEmulator) seed(_ *testing.T, path, value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.data["inv237/"+path] = value
	e.vers["inv237/"+path] = 1
}

// openBaoProbe reads a real OpenBao KV v2 mount over its HTTP API (lab mode).
type openBaoProbe struct {
	addr, token, prefix string
	client              *http.Client
}

func (o openBaoProbe) do(t *testing.T, method, path string, body io.Reader) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), method, o.addr+path, body)
	req.Header.Set("X-Vault-Token", o.token)
	resp, err := o.client.Do(req)
	if err != nil {
		t.Fatalf("openbao %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (o openBaoProbe) value(t *testing.T, path string) (string, bool) {
	status, out := o.do(t, http.MethodGet, "/v1/secret/data/"+o.prefix+"/inv237/"+path, nil)
	if status == http.StatusNotFound {
		return "", false
	}
	data, _ := out["data"].(map[string]any)
	inner, _ := data["data"].(map[string]any)
	v, _ := inner["value"].(string)
	return v, true
}

func (o openBaoProbe) versions(t *testing.T, path string) int {
	status, out := o.do(t, http.MethodGet, "/v1/secret/metadata/"+o.prefix+"/inv237/"+path, nil)
	if status == http.StatusNotFound {
		return 0
	}
	data, _ := out["data"].(map[string]any)
	n, _ := data["current_version"].(float64)
	return int(n)
}

func (o openBaoProbe) seed(t *testing.T, path, value string) {
	raw, _ := json.Marshal(map[string]any{"data": map[string]string{"value": value}})
	if status, _ := o.do(t, http.MethodPost, "/v1/secret/data/"+o.prefix+"/inv237/"+path, strings.NewReader(string(raw))); status != http.StatusOK {
		t.Fatalf("seed %s: HTTP %d", path, status)
	}
}

// A237: a scoped sync of one environment to a KV v2 destination — create,
// update and delete with readback, an unmanaged key that survives, a nested
// key and an existing key refused in the plan, a crash after the remote write
// that resumes without a second write, and a source change after the preview
// that makes the plan stale. With TRSTCTL_A237_LAB_OPENBAO_ADDR and
// TRSTCTL_A237_LAB_OPENBAO_TOKEN the destination is a real OpenBao.
func TestServedScopedSecretSyncKeepsUnmanagedKeysAndResumesA237(t *testing.T) {
	const token = "a237-kv-token" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	var probe kvProbe
	var pusher *secretsync.VaultKVV2Pusher
	var err error
	if addr := os.Getenv("TRSTCTL_A237_LAB_OPENBAO_ADDR"); addr != "" {
		labToken := os.Getenv("TRSTCTL_A237_LAB_OPENBAO_TOKEN")
		prefix := "trstctl-a237-" + time.Now().UTC().Format("20060102t150405")
		// The lab target is loopback; it gets its own transport, not the
		// process's hardened default.
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{}}
		probe = openBaoProbe{addr: addr, token: labToken, prefix: prefix, client: client}
		pusher, err = secretsync.NewVaultKVV2Pusher(secretsync.VaultKVV2Config{
			Endpoint: addr, HTTPClient: client, Token: []byte(labToken), Mount: "secret", PathPrefix: prefix,
		})
		t.Logf("A237 lab mode: OpenBao at %s, prefix %s", addr, prefix)
	} else {
		emulator := newScopedKVEmulator(t, token)
		probe = emulator
		pusher, err = secretsync.NewVaultKVV2Pusher(secretsync.VaultKVV2Config{
			Endpoint: emulator.server.URL, HTTPClient: emulator.server.Client(), Token: []byte(token), Mount: "kv", PathPrefix: "apps",
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pusher.Close)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = SecretSyncTargetRegistry{servedTestTenant: {"kv": secretsync.NewTarget("kv", pusher)}}
	})
	registerServedTenant(t, h, "A237 scoped sync tenant")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "a237-operator", "secrets:read", "secrets:write")
	write := func(method, name, value string) {
		t.Helper()
		path, body, want := "/api/v1/secrets/store", map[string]any{"name": name, "value": value}, http.StatusCreated
		if method == http.MethodPut {
			path, body, want = "/api/v1/secrets/store/"+name, map[string]any{"value": value}, http.StatusOK
		}
		if status, raw := secretsReqKey(t, h, method, path, tok, "a237-"+method+"-"+name+"-"+value, body); status != want {
			t.Fatalf("%s %s: HTTP %d %s", method, name, status, raw)
		}
	}
	type planView struct {
		PlanDigest string `json:"plan_digest"`
		Items      []struct {
			Key    string `json:"key"`
			Action string `json:"action"`
			Reason string `json:"reason"`
		} `json:"items"`
		Changes int `json:"changes"`
		Blocked int `json:"blocked"`
	}
	action := func(p planView, key string) (string, string) {
		for _, item := range p.Items {
			if item.Key == key {
				return item.Action, item.Reason
			}
		}
		return "", ""
	}
	drain := func() {
		t.Helper()
		for range 3 {
			// Sync jobs wait for the projection checkpoint to pass their event;
			// this harness runs no live projector, so the test advances it.
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

	write(http.MethodPost, "inv237/prod/db/password", "pw-one")
	write(http.MethodPost, "inv237/prod/api/token", "tok-one")
	probe.seed(t, "legacy", "keep-me")
	status, defRaw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scoped-syncs", tok, "a237-define", map[string]any{
		"name": "inv237-prod", "source_prefix": "inv237/prod/", "target": "kv", "destination_prefix": "inv237", "delete_scope": "managed",
	})
	var def struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(defRaw, &def) != nil || def.ID == "" {
		t.Fatalf("define: HTTP %d %s", status, defRaw)
	}
	base := "/api/v1/secrets/scoped-syncs/" + def.ID
	preview := func() (planView, string) {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodPost, base+"/preview", tok, nil)
		var p planView
		if status != http.StatusOK || json.Unmarshal(raw, &p) != nil {
			t.Fatalf("preview: HTTP %d %s", status, raw)
		}
		for _, v := range []string{"pw-one", "pw-two", "tok-one", "tok-two", "keep-me"} {
			if strings.Contains(string(raw), v) {
				t.Fatalf("the plan carries a value (%q): %s", v, raw)
			}
		}
		return p, string(raw)
	}
	apply := func(key, digest string) (int, string) {
		status, raw := secretsReqKey(t, h, http.MethodPost, base+"/apply", tok, key, map[string]any{"plan_digest": digest})
		return status, string(raw)
	}

	plan, raw := preview()
	if a, _ := action(plan, "inv237/db/password"); a != "create" || plan.Changes != 2 {
		t.Fatalf("first plan: %s", raw)
	}
	if a, _ := action(plan, "inv237/legacy"); a != "unmanaged" {
		t.Fatalf("the unmanaged key is not listed as such: %s", raw)
	}
	// A source changed after the preview makes the reviewed plan stale.
	write(http.MethodPut, "inv237/prod/db/password", "pw-two")
	if status, body := apply("a237-apply-stale", plan.PlanDigest); status != http.StatusConflict || !strings.Contains(body, "plan_stale") {
		t.Fatalf("stale apply: HTTP %d %s", status, body)
	}

	// A crash after the remote write but before the delivery is recorded: the
	// retry reads the destination back and settles without a second write.
	dispatch, ok := h.srv.obHandler.(*issuanceDispatcher)
	if !ok || dispatch.secretIntegrations == nil {
		t.Fatal("secret integration dispatcher is not assembled")
	}
	var crashed sync.Once
	var crashes, deliveries int
	dispatch.secretIntegrations.afterSecretSyncDelivery = func(_ context.Context, payload secretSyncOutboxPayload) error {
		err := error(nil)
		if payload.Key == "inv237/db/password" {
			deliveries++
			crashed.Do(func() { crashes++; err = errors.New("forced crash after the receiver committed") })
		}
		return err
	}
	plan, _ = preview()
	if status, body := apply("a237-apply-1", plan.PlanDigest); status != http.StatusCreated || !strings.Contains(body, `"writes"`) {
		t.Fatalf("apply: HTTP %d %s", status, body)
	}
	drain()
	if v, ok := probe.value(t, "db/password"); !ok || v != "pw-two" {
		t.Fatalf("destination db/password = %q %v", v, ok)
	}
	if crashes != 1 {
		t.Fatalf("the forced crash after the remote write did not happen (%d)", crashes)
	}
	if n := probe.versions(t, "db/password"); n != 1 {
		t.Fatalf("the retry after the crash wrote again: %d versions", n)
	}
	t.Logf("crash after remote write: %d crash, %d receiver passes, %d destination version", crashes, deliveries, probe.versions(t, "db/password"))
	if v, _ := probe.value(t, "api/token"); v != "tok-one" {
		t.Fatalf("destination api/token = %q", v)
	}

	// Update: a rotated source is one update; only that key gets a version.
	write(http.MethodPut, "inv237/prod/api/token", "tok-two")
	plan, raw = preview()
	if a, _ := action(plan, "inv237/api/token"); a != "update" || plan.Changes != 1 {
		t.Fatalf("update plan: %s", raw)
	}
	if a, _ := action(plan, "inv237/db/password"); a != "unchanged" {
		t.Fatalf("an unchanged key: %s", raw)
	}
	if status, body := apply("a237-apply-2", plan.PlanDigest); status != http.StatusCreated {
		t.Fatalf("apply update: HTTP %d %s", status, body)
	}
	drain()
	if v, _ := probe.value(t, "api/token"); v != "tok-two" {
		t.Fatalf("updated api/token = %q", v)
	}

	// Delete: the source is gone, the managed key goes, the unmanaged one stays.
	if status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/inv237/prod/api/token", tok, "a237-delete-src", nil); status != http.StatusOK && status != http.StatusNoContent {
		t.Fatalf("delete source: HTTP %d %s", status, body)
	}
	plan, raw = preview()
	if a, _ := action(plan, "inv237/api/token"); a != "delete" || plan.Changes != 1 {
		t.Fatalf("delete plan: %s", raw)
	}
	if status, body := apply("a237-apply-3", plan.PlanDigest); status != http.StatusCreated || !strings.Contains(body, "delete_id") {
		t.Fatalf("apply delete: HTTP %d %s", status, body)
	}
	drain()
	if _, ok := probe.value(t, "api/token"); ok {
		t.Fatal("the managed key whose source is gone was not deleted")
	}
	if v, ok := probe.value(t, "legacy"); !ok || v != "keep-me" {
		t.Fatalf("the unmanaged key did not survive: %q %v", v, ok)
	}

	// Collisions are refused in the plan: a key that would also be a folder,
	// and an existing key this sync didn't write.
	write(http.MethodPost, "inv237/prod/db", "nested")
	write(http.MethodPost, "inv237/prod/legacy", "takeover")
	plan, raw = preview()
	if a, reason := action(plan, "inv237/db"); a != "blocked" || !strings.Contains(reason, "can't also be a folder") {
		t.Fatalf("nested key: %s", raw)
	}
	if a, reason := action(plan, "inv237/legacy"); a != "blocked" || !strings.Contains(reason, "didn't write") {
		t.Fatalf("existing unmanaged key: %s", raw)
	}
	if status, body := apply("a237-apply-4", plan.PlanDigest); status != http.StatusConflict || !strings.Contains(body, "plan_blocked") {
		t.Fatalf("blocked apply: HTTP %d %s", status, body)
	}
	if v, _ := probe.value(t, "legacy"); v != "keep-me" {
		t.Fatalf("a blocked plan touched the unmanaged key: %q", v)
	}

	// The definition shows the keys it manages with their delivery status.
	status, shownRaw := secretsReq(t, h, http.MethodGet, base, tok, nil)
	var shown struct {
		Keys []struct {
			Key       string `json:"key"`
			JobStatus string `json:"job_status"`
		} `json:"keys"`
	}
	if status != http.StatusOK || json.Unmarshal(shownRaw, &shown) != nil || len(shown.Keys) != 1 ||
		shown.Keys[0].Key != "inv237/db/password" || shown.Keys[0].JobStatus != string(store.SecretSyncJobDelivered) {
		t.Fatalf("definition view: HTTP %d %s", status, shownRaw)
	}
	// Drift: a destination changed outside the sync plans as an update, named.
	for _, name := range []string{"inv237/prod/db", "inv237/prod/legacy"} {
		if status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/"+name, tok, "a237-cleanup-"+name, nil); status != http.StatusOK && status != http.StatusNoContent {
			t.Fatalf("remove %s: HTTP %d %s", name, status, body)
		}
	}
	probe.seed(t, "db/password", "tampered")
	plan, raw = preview()
	if a, reason := action(plan, "inv237/db/password"); a != "update" || !strings.Contains(reason, "drift") {
		t.Fatalf("drift: %s", raw)
	}
	// A reviewed delete scope of every key under the prefix includes keys the
	// sync didn't write: a sweep definition with no sources deletes both.
	status, defRaw = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scoped-syncs", tok, "a237-define-sweep", map[string]any{
		"name": "inv237-sweep", "source_prefix": "inv237/none/", "target": "kv", "destination_prefix": "inv237", "delete_scope": "prefix",
	})
	var sweep struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(defRaw, &sweep) != nil {
		t.Fatalf("define sweep: HTTP %d %s", status, defRaw)
	}
	status, sweepRaw := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/scoped-syncs/"+sweep.ID+"/preview", tok, nil)
	var sweepPlan planView
	if status != http.StatusOK || json.Unmarshal(sweepRaw, &sweepPlan) != nil || sweepPlan.Changes != 2 {
		t.Fatalf("sweep plan: HTTP %d %s", status, sweepRaw)
	}
	if a, _ := action(sweepPlan, "inv237/legacy"); a != "delete" {
		t.Fatalf("the prefix scope does not include the unmanaged key: %s", sweepRaw)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scoped-syncs/"+sweep.ID+"/apply", tok, "a237-apply-sweep",
		map[string]any{"plan_digest": sweepPlan.PlanDigest}); status != http.StatusCreated {
		t.Fatalf("apply sweep: HTTP %d %s", status, body)
	}
	drain()
	if _, ok := probe.value(t, "legacy"); ok {
		t.Fatal("a key inside the reviewed prefix scope survived")
	}
	if h.logContains(t, "pw-two") || h.logContains(t, "tok-two") {
		t.Fatal("a value reached the logs")
	}
	t.Logf("A237_SCOPED_SYNC_OK")
}
