// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/synctarget"
)

// A241: every hosted secret-sync target is proven through the served API by
// one journey, hostedSyncProof: a config-built target, a scoped sync of an
// environment that creates, updates and deletes keys, an unmanaged key that
// survives, a nested source refused for a flat destination until the env
// transform names it, drift seen where the destination reads back (and named
// receipt-only where it can't), the catalog row, and no value in a plan or
// the logs. Each target's stand-in is built from the vendor's API reference.

// syncStandIn is a vendor double: an in-memory destination behind the
// vendor's API shape.
type syncStandIn struct {
	server *httptest.Server
	mu     sync.Mutex
	vars   map[string]string
	calls  []string
}

func newSyncStandIn(t *testing.T, serve func(s *syncStandIn, w http.ResponseWriter, r *http.Request)) *syncStandIn {
	t.Helper()
	s := &syncStandIn{vars: map[string]string{}}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.calls = append(s.calls, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		if serve != nil {
			serve(s, w, r)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *syncStandIn) value(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.vars[name]
	return v, ok
}

func (s *syncStandIn) seed(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vars[name] = value
}

func (s *syncStandIn) names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.vars))
	for name := range s.vars {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// hostedSyncCase is one target's journey settings.
type hostedSyncCase struct {
	typ      string
	endpoint string
	binding  string
	username string
	token    string
	standIn  *syncStandIn
	// path is true for a destination that holds paths, not variable names.
	path bool
	// remote maps a destination key to the stand-in's name for it (a vendor
	// may decorate names, for example Zabbix macros); nil is identity.
	remote func(key string) string
	// seed overrides putting a value at the destination outside the sync
	// (for a stand-in whose state is not the map, such as a file).
	seed func(name, value string)
}

func (c hostedSyncCase) put(name, value string) {
	if c.seed != nil {
		c.seed(name, value)
		return
	}
	c.standIn.seed(name, value)
}

func (c hostedSyncCase) name(key string) string {
	if c.remote != nil {
		return c.remote(key)
	}
	return key
}

// hostedSyncProof runs the A241 journey for one hosted target.
func hostedSyncProof(t *testing.T, c hostedSyncCase) {
	t.Helper()
	ctx := context.Background()
	registry, minter, err := secretSyncTargetsFromConfig(ctx, []config.SecretSyncTargetConfig{{
		TenantID: servedTestTenant, ID: "hosted", Type: c.typ, Endpoint: c.endpoint, AllowInsecureLoopback: true,
		TokenRef: writeServedCredentialFile(t, c.typ+"-token", c.token), Binding: c.binding, Username: c.username,
	}}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(minter.Close)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = registry
	})
	registerServedTenant(t, h, "A241 "+c.typ+" tenant")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "a241-operator-"+c.typ, "secrets:read", "secrets:write")
	// The served harness shares its tenant across tests: every name here is
	// the target type's own.
	ns := strings.ReplaceAll(c.typ, "_", "-")
	write := func(method, name, value string) {
		t.Helper()
		path, body, want := "/api/v1/secrets/store", map[string]any{"name": name, "value": value}, http.StatusCreated
		if method == http.MethodPut {
			path, body, want = "/api/v1/secrets/store/"+name, map[string]any{"value": value}, http.StatusOK
		}
		if status, raw := secretsReqKey(t, h, method, path, tok, "a241-"+ns+"-"+method+"-"+name+"-"+value, body); status != want {
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
	values := []string{"pw-one-a241", "pw-two-a241", "tok-one-a241", "tok-two-a241", "keep-me-a241", "nested-a241"}
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
			drainCtx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			_ = h.srv.Drain(drainCtx)
			cancel()
		}
	}
	// Keys: a flat destination holds DB_PASSWORD under the prefix APP_; a
	// path destination holds inv241/db_password.
	prefix, transform, dbName, apiName, legacy := "APP_", "env", "APP_DB_PASSWORD", "APP_API_TOKEN", "APP_LEGACY"
	if c.path {
		prefix, transform, dbName, apiName, legacy = "inv241", "path", "inv241/db_password", "inv241/api_token", "inv241/legacy"
	}
	write(http.MethodPost, "a241/"+ns+"/prod/db_password", "pw-one-a241")
	write(http.MethodPost, "a241/"+ns+"/prod/api_token", "tok-one-a241")
	c.put(c.name(legacy), "keep-me-a241")
	status, defRaw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scoped-syncs", tok, "a241-define-"+ns, map[string]any{
		"name": ns + "-prod", "source_prefix": "a241/" + ns + "/prod/", "target": "hosted", "destination_prefix": prefix,
		"key_transform": transform, "delete_scope": "managed",
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
		for _, v := range values {
			if strings.Contains(string(raw), v) {
				t.Fatalf("the plan carries a value (%q): %s", v, raw)
			}
		}
		return p, string(raw)
	}
	action := func(p planView, key string) (string, string) {
		for _, item := range p.Items {
			if item.Key == key {
				return item.Action, item.Reason
			}
		}
		return "", ""
	}
	apply := func(idem string, p planView) {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, base+"/apply", tok, idem, map[string]any{"plan_digest": p.PlanDigest})
		if status != http.StatusCreated {
			t.Fatalf("apply %s: HTTP %d %s", idem, status, raw)
		}
		drain()
	}
	holds := func(key, want string) {
		t.Helper()
		if got, ok := c.standIn.value(c.name(key)); !ok || got != want {
			t.Fatalf("%s holds %s = %q (present %v), want %q; it holds %v", c.typ, key, got, ok, want, c.standIn.names())
		}
	}

	// Create: both keys, the unmanaged one listed and left alone.
	plan, raw := preview()
	if a, _ := action(plan, dbName); a != "create" || plan.Changes != 2 {
		t.Fatalf("first plan: %s", raw)
	}
	if a, _ := action(plan, legacy); a != "unmanaged" {
		t.Fatalf("the unmanaged key is not listed as such: %s", raw)
	}
	apply("a241-apply-1-"+ns, plan)
	holds(dbName, "pw-one-a241")
	holds(apiName, "tok-one-a241")

	// Update: a rotated source is one update; the other key is unchanged.
	write(http.MethodPut, "a241/"+ns+"/prod/api_token", "tok-two-a241")
	plan, raw = preview()
	readsBack := secretsync.HostedReadBack(c.typ) != secretsync.ReadBackReceiptOnly
	if a, reason := action(plan, apiName); a != "update" || plan.Changes != 1 || (!readsBack && !strings.Contains(reason, "receipt-only")) {
		t.Fatalf("update plan: %s", raw)
	}
	if a, reason := action(plan, dbName); a != "unchanged" || (!readsBack && !strings.Contains(reason, "receipt-only")) {
		t.Fatalf("an unchanged key: %s", raw)
	}
	apply("a241-apply-2-"+ns, plan)
	holds(apiName, "tok-two-a241")

	// Drift: a value changed at the destination is an update named drift
	// where the destination reads back; a receipt-only one can't see it and
	// says so.
	c.put(c.name(dbName), "tampered-a241")
	plan, raw = preview()
	if a, reason := action(plan, dbName); readsBack && (a != "update" || !strings.Contains(reason, "drift")) {
		t.Fatalf("drift: %s", raw)
	} else if !readsBack && (a != "unchanged" || !strings.Contains(reason, "can't be seen")) {
		t.Fatalf("receipt-only drift: %s", raw)
	}
	if readsBack {
		apply("a241-apply-drift-"+ns, plan)
		holds(dbName, "pw-one-a241")
	} else {
		c.put(c.name(dbName), "pw-one-a241")
	}

	// Delete: the source is gone, the managed key goes, the unmanaged stays.
	if status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/a241/"+ns+"/prod/api_token", tok, "a241-delete-src-"+ns, nil); status != http.StatusOK && status != http.StatusNoContent {
		t.Fatalf("delete source: HTTP %d %s", status, body)
	}
	plan, raw = preview()
	if a, _ := action(plan, apiName); a != "delete" || plan.Changes != 1 {
		t.Fatalf("delete plan: %s", raw)
	}
	apply("a241-apply-3-"+ns, plan)
	if _, ok := c.standIn.value(c.name(apiName)); ok {
		t.Fatalf("the managed key whose source is gone was not deleted: %v", c.standIn.names())
	}
	holds(legacy, "keep-me-a241")

	// A flat destination whose names exclude slashes can't hold a path: a
	// nested source is blocked under the path transform and named with env.
	if target, _ := synctarget.Lookup(c.typ); !c.path && target.ValidKey("db/password") != nil {
		write(http.MethodPost, "a241/"+ns+"/flat/db/password", "nested-a241")
		status, rawDef := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scoped-syncs", tok, "a241-define-flat-"+ns, map[string]any{
			"name": ns + "-flat", "source_prefix": "a241/" + ns + "/flat/", "target": "hosted", "key_transform": "path",
		})
		var flat struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(rawDef, &flat) != nil {
			t.Fatalf("define flat: HTTP %d %s", status, rawDef)
		}
		status, rawPlan := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/scoped-syncs/"+flat.ID+"/preview", tok, nil)
		if status != http.StatusOK || !strings.Contains(string(rawPlan), `"blocked"`) || !strings.Contains(string(rawPlan), "key_transform env") {
			t.Fatalf("a path key for a flat destination: HTTP %d %s", status, rawPlan)
		}
	}

	// The catalog says what the target is and how far it is proven.
	status, catalogRaw := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/syncs/targets", tok, nil)
	var catalog struct {
		Targets []struct {
			ID         string `json:"id"`
			Configured bool   `json:"configured"`
			ScopedSync bool   `json:"scoped_sync"`
			ReadBack   string `json:"readback"`
			Proof      string `json:"proof"`
		} `json:"targets"`
	}
	if status != http.StatusOK || json.Unmarshal(catalogRaw, &catalog) != nil {
		t.Fatalf("catalog: HTTP %d %s", status, catalogRaw)
	}
	found := false
	for _, row := range catalog.Targets {
		if row.ID == c.typ {
			found = true
			if !row.ScopedSync || row.ReadBack != string(secretsync.HostedReadBack(c.typ)) || row.Proof == "" {
				t.Fatalf("catalog row for %s: %+v", c.typ, row)
			}
		}
	}
	if !found {
		t.Fatalf("the catalog has no %s row: %s", c.typ, catalogRaw)
	}
	for _, v := range values {
		if h.logContains(t, v) {
			t.Fatalf("a value reached the logs: %q", v)
		}
	}
	t.Logf("A241_%s_OK readback=%s calls=%d", strings.ToUpper(strings.ReplaceAll(c.typ, "-", "_")), secretsync.HostedReadBack(c.typ), len(c.standIn.calls))
}

// jsonStandIn writes v as a JSON answer.
func jsonStandIn(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// TestServedHerokuScopedSyncA241: Heroku config vars, from the Platform API
// reference: PATCH /apps/{app}/config-vars sets (null deletes), GET returns
// every var with its value; Bearer token and the version-3 Accept header.
func TestServedHerokuScopedSyncA241(t *testing.T) {
	const token = "heroku-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Accept") != "application/vnd.heroku+json; version=3" {
			jsonStandIn(w, http.StatusUnauthorized, map[string]string{"id": "unauthorized"})
			return
		}
		if r.URL.Path != "/apps/payments-a241/config-vars" {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"id": "not_found"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
		case http.MethodPatch:
			var patch map[string]*string
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				jsonStandIn(w, http.StatusBadRequest, map[string]string{"id": "bad_request"})
				return
			}
			for name, value := range patch {
				if value == nil {
					delete(s.vars, name)
				} else {
					s.vars[name] = *value
				}
			}
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, map[string]string{"id": "method_not_allowed"})
			return
		}
		jsonStandIn(w, http.StatusOK, s.vars)
	})
	hostedSyncProof(t, hostedSyncCase{typ: "heroku", endpoint: standIn.server.URL, binding: "payments-a241", token: token, standIn: standIn})
}

// standInAuth refuses a request without the expected header value.
func standInAuth(w http.ResponseWriter, r *http.Request, header, want string) bool {
	if r.Header.Get(header) != want {
		jsonStandIn(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return false
	}
	return true
}

func decodeStandIn(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		jsonStandIn(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return false
	}
	return true
}

// TestServedRenderScopedSyncA241: Render's API reference — PUT
// /services/{id}/env-vars/{key} {value}, DELETE (204), GET one {key,value},
// GET the list as [{envVar:{key,value},cursor}] pages.
func TestServedRenderScopedSyncA241(t *testing.T) {
	const token = "render-a241-key" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/services/srv-a241payments/env-vars")
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		key := strings.TrimPrefix(rest, "/")
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case key == "" && r.Method == http.MethodGet:
			names := make([]string, 0, len(s.vars))
			for name := range s.vars {
				names = append(names, name)
			}
			sort.Strings(names)
			page := []map[string]any{}
			for _, name := range names {
				page = append(page, map[string]any{"envVar": map[string]string{"key": name, "value": s.vars[name]}, "cursor": "c-" + name})
			}
			jsonStandIn(w, http.StatusOK, page)
		case r.Method == http.MethodPut:
			var body struct {
				Value string `json:"value"`
			}
			if !decodeStandIn(w, r, &body) {
				return
			}
			s.vars[key] = body.Value
			jsonStandIn(w, http.StatusOK, map[string]string{"key": key, "value": body.Value})
		case r.Method == http.MethodGet:
			v, ok := s.vars[key]
			if !ok {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
				return
			}
			jsonStandIn(w, http.StatusOK, map[string]string{"key": key, "value": v})
		case r.Method == http.MethodDelete:
			if _, ok := s.vars[key]; !ok {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
				return
			}
			delete(s.vars, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "render", endpoint: standIn.server.URL, binding: "srv-a241payments", token: token, standIn: standIn})
}

// TestServedRailwayScopedSyncA241: Railway's public GraphQL API —
// variableUpsert / variableDelete mutations with an input object, and the
// variables query answering a JSON map of names to values.
func TestServedRailwayScopedSyncA241(t *testing.T) {
	const token = "railway-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	const project, environment = "11111111-2222-4333-8444-555555555555", "66666666-7777-4888-8999-aaaaaaaaaaaa"
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		var req struct {
			Query     string `json:"query"`
			Variables struct {
				ProjectID     string `json:"projectId"`
				EnvironmentID string `json:"environmentId"`
				Input         struct {
					ProjectID     string  `json:"projectId"`
					EnvironmentID string  `json:"environmentId"`
					Name          string  `json:"name"`
					Value         *string `json:"value"`
					SkipDeploys   bool    `json:"skipDeploys"`
				} `json:"input"`
			} `json:"variables"`
		}
		if r.Method != http.MethodPost || !decodeStandIn(w, r, &req) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		in := req.Variables.Input
		switch {
		case strings.Contains(req.Query, "variableUpsert(input: $input)"):
			if in.ProjectID != project || in.EnvironmentID != environment || in.Value == nil || !in.SkipDeploys {
				jsonStandIn(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "bad input"}}})
				return
			}
			s.vars[in.Name] = *in.Value
			jsonStandIn(w, http.StatusOK, map[string]any{"data": map[string]bool{"variableUpsert": true}})
		case strings.Contains(req.Query, "variableDelete(input: $input)"):
			if _, ok := s.vars[in.Name]; !ok {
				jsonStandIn(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "not found"}}})
				return
			}
			delete(s.vars, in.Name)
			jsonStandIn(w, http.StatusOK, map[string]any{"data": map[string]bool{"variableDelete": true}})
		case strings.Contains(req.Query, "variables(projectId: $projectId"):
			if req.Variables.ProjectID != project || req.Variables.EnvironmentID != environment {
				jsonStandIn(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "not found"}}})
				return
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"data": map[string]any{"variables": s.vars}})
		default:
			jsonStandIn(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "unknown operation"}}})
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "railway", endpoint: standIn.server.URL, binding: "project " + project + " environment " + environment, token: token, standIn: standIn})
}

// TestServedFlyScopedSyncA241: Fly.io's Machines API — POST
// /v1/apps/{app}/secrets/{name} {value}, DELETE, and a list of names with a
// keyed digest that can't be recomputed (receipt-only).
func TestServedFlyScopedSyncA241(t *testing.T) {
	const token = "fly-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/v1/apps/payments-a241/secrets")
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"error": "app not found"})
			return
		}
		name := strings.TrimPrefix(rest, "/")
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case name == "" && r.Method == http.MethodGet:
			list := []map[string]string{}
			for _, n := range sortedKeys(s.vars) {
				list = append(list, map[string]string{"name": n, "digest": "keyed-" + n})
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"secrets": list})
		case r.Method == http.MethodPost:
			var body struct {
				Value string `json:"value"`
			}
			if !decodeStandIn(w, r, &body) {
				return
			}
			s.vars[name] = body.Value
			jsonStandIn(w, http.StatusCreated, map[string]any{"name": name, "digest": "keyed", "version": 2})
		case r.Method == http.MethodDelete:
			delete(s.vars, name)
			jsonStandIn(w, http.StatusOK, map[string]int{"version": 3})
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "fly", endpoint: standIn.server.URL, binding: "payments-a241", token: token, standIn: standIn})
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestServedDigitalOceanAppPlatformScopedSyncA241: the App Platform API —
// GET /v2/apps/{id} returns the spec; PUT /v2/apps/{id} {spec} replaces it.
// A SECRET env reads back as EV[...] ciphertext (receipt-only); the stand-in
// checks that the rest of the spec (a service and a plain env) round-trips.
func TestServedDigitalOceanAppPlatformScopedSyncA241(t *testing.T) {
	const token = "do-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	const app = "0f0e0d0c-0b0a-4908-8706-050403020100"
	var specMu sync.Mutex
	other := map[string]any{"name": "web", "github": map[string]any{"repo": "acme/web", "branch": "main"}}
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		if r.URL.Path != "/v2/apps/"+app {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"id": "not_found"})
			return
		}
		specMu.Lock()
		defer specMu.Unlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			envs := []map[string]string{{"key": "PLAIN_SETTING", "value": "visible", "type": "GENERAL", "scope": "RUN_TIME"}}
			for _, k := range sortedKeys(s.vars) {
				envs = append(envs, map[string]string{"key": k, "value": "EV[1:abc:" + k + "]", "type": "SECRET", "scope": "RUN_AND_BUILD_TIME"})
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"app": map[string]any{"id": app, "spec": map[string]any{
				"name": "payments", "region": "nyc", "services": []any{other}, "envs": envs,
			}}})
		case http.MethodPut:
			var body struct {
				Spec struct {
					Name     string           `json:"name"`
					Region   string           `json:"region"`
					Services []map[string]any `json:"services"`
					Envs     []struct {
						Key, Value, Type, Scope string
					} `json:"envs"`
				} `json:"spec"`
			}
			if !decodeStandIn(w, r, &body) {
				return
			}
			if body.Spec.Name != "payments" || body.Spec.Region != "nyc" || len(body.Spec.Services) != 1 || body.Spec.Services[0]["name"] != "web" {
				jsonStandIn(w, http.StatusUnprocessableEntity, map[string]string{"id": "unprocessable_entity", "message": "the spec lost its other parts"})
				return
			}
			next := map[string]string{}
			plain := false
			for _, env := range body.Spec.Envs {
				switch {
				case env.Key == "PLAIN_SETTING":
					plain = env.Value == "visible" && env.Type == "GENERAL"
				case strings.HasPrefix(env.Value, "EV["):
					next[env.Key] = s.vars[env.Key] // unchanged ciphertext resubmitted
				case env.Type == "SECRET":
					next[env.Key] = env.Value
				}
			}
			if !plain {
				jsonStandIn(w, http.StatusUnprocessableEntity, map[string]string{"id": "unprocessable_entity", "message": "the plain env changed"})
				return
			}
			s.vars = next
			jsonStandIn(w, http.StatusOK, map[string]any{"app": map[string]string{"id": app}})
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "digitalocean-app-platform", endpoint: standIn.server.URL, binding: "app " + app, token: token, standIn: standIn})
}

// TestServedNorthflankScopedSyncA241: Northflank secret groups — GET
// /projects/{p}/secrets/{id} returns data.secrets.variables; PATCH with
// secrets.variables replaces the whole map.
func TestServedNorthflankScopedSyncA241(t *testing.T) {
	const token = "northflank-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		if r.URL.Path != "/projects/payments/secrets/runtime-a241" {
			jsonStandIn(w, http.StatusNotFound, map[string]any{"error": map[string]string{"message": "not found"}})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			jsonStandIn(w, http.StatusOK, map[string]any{"data": map[string]any{"id": "runtime-a241", "secrets": map[string]any{"variables": s.vars}}})
		case http.MethodPatch:
			var body struct {
				Secrets struct {
					Variables map[string]string `json:"variables"`
				} `json:"secrets"`
			}
			if !decodeStandIn(w, r, &body) {
				return
			}
			s.vars = body.Secrets.Variables
			if s.vars == nil {
				s.vars = map[string]string{}
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"data": map[string]string{"id": "runtime-a241"}})
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "northflank", endpoint: standIn.server.URL, binding: "project payments secret-group runtime-a241", token: token, standIn: standIn})
}

// TestServedQoveryScopedSyncA241: Qovery's variable API — POST /variable
// creates (409 on a duplicate), PUT /variable/{id} updates, DELETE removes,
// and GET /variable?parent_id=&scope= lists with a secret's value null.
func TestServedQoveryScopedSyncA241(t *testing.T) {
	const token = "qovery-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	const parent = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	ids := map[string]string{}
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Token "+token) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		idOf := func(key string) string {
			if ids[key] == "" {
				ids[key] = "var-" + strings.ToLower(key)
			}
			return ids[key]
		}
		keyOf := func(id string) string {
			for k, v := range ids {
				if v == id {
					if _, live := s.vars[k]; live {
						return k
					}
				}
			}
			return ""
		}
		switch {
		case r.URL.Path == "/variable" && r.Method == http.MethodGet:
			if r.URL.Query().Get("parent_id") != parent || r.URL.Query().Get("scope") != "APPLICATION" {
				jsonStandIn(w, http.StatusOK, map[string]any{"results": []any{}})
				return
			}
			results := []map[string]any{{"id": "builtin-1", "key": "QOVERY_APPLICATION_ID", "value": parent, "is_secret": false, "scope": "BUILT_IN"}}
			for _, k := range sortedKeys(s.vars) {
				results = append(results, map[string]any{"id": idOf(k), "key": k, "value": nil, "is_secret": true, "scope": "APPLICATION"})
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"results": results})
		case r.URL.Path == "/variable" && r.Method == http.MethodPost:
			var body struct {
				Key, Value, VariableScope, VariableParentID string
				IsSecret                                    bool `json:"is_secret"`
			}
			raw := map[string]any{}
			if !decodeStandIn(w, r, &raw) {
				return
			}
			body.Key, _ = raw["key"].(string)
			body.Value, _ = raw["value"].(string)
			body.VariableScope, _ = raw["variable_scope"].(string)
			body.VariableParentID, _ = raw["variable_parent_id"].(string)
			body.IsSecret, _ = raw["is_secret"].(bool)
			if body.VariableScope != "APPLICATION" || body.VariableParentID != parent || !body.IsSecret {
				jsonStandIn(w, http.StatusBadRequest, map[string]string{"message": "bad variable"})
				return
			}
			if _, exists := s.vars[body.Key]; exists {
				jsonStandIn(w, http.StatusConflict, map[string]string{"message": "exists"})
				return
			}
			s.vars[body.Key] = body.Value
			jsonStandIn(w, http.StatusCreated, map[string]string{"id": idOf(body.Key), "key": body.Key})
		case strings.HasPrefix(r.URL.Path, "/variable/"):
			id := strings.TrimPrefix(r.URL.Path, "/variable/")
			key := keyOf(id)
			if key == "" {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "Resource not found"})
				return
			}
			switch r.Method {
			case http.MethodPut:
				var body struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				}
				if !decodeStandIn(w, r, &body) || body.Key != key {
					return
				}
				s.vars[key] = body.Value
				jsonStandIn(w, http.StatusOK, map[string]string{"id": id, "key": key})
			case http.MethodDelete:
				delete(s.vars, key)
				w.WriteHeader(http.StatusNoContent)
			}
		default:
			jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "qovery", endpoint: standIn.server.URL, binding: "application " + parent, token: token, standIn: standIn})
}

// TestServedCloud66ScopedSyncA241: Cloud 66 API v3 — POST
// /stacks/{s}/environments {key,value}, PUT /stacks/{s}/environments/{key}
// {value}, DELETE, and GET listing {response:[{key,value}],pagination}.
func TestServedCloud66ScopedSyncA241(t *testing.T) {
	const token = "cloud66-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/stacks/stack-a241-payments/environments")
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		key := strings.TrimPrefix(rest, "/")
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case key == "" && r.Method == http.MethodGet:
			list := []map[string]any{{"id": 1, "key": "STACK_BASE_URL", "value": "https://payments.example", "readonly": true}}
			for i, k := range sortedKeys(s.vars) {
				if k == "STACK_BASE_URL" {
					continue
				}
				list = append(list, map[string]any{"id": i + 2, "key": k, "value": s.vars[k], "readonly": false})
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"response": list, "count": len(list), "pagination": map[string]any{"current": 1, "next": nil, "pages": 1}})
		case key == "" && r.Method == http.MethodPost:
			var body struct{ Key, Value string }
			if !decodeStandIn(w, r, &body) {
				return
			}
			s.vars[body.Key] = body.Value
			jsonStandIn(w, http.StatusOK, map[string]any{"response": map[string]string{"key": body.Key}})
		case r.Method == http.MethodPut:
			var body struct{ Value string }
			if !decodeStandIn(w, r, &body) {
				return
			}
			if _, ok := s.vars[key]; !ok {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			s.vars[key] = body.Value
			jsonStandIn(w, http.StatusOK, map[string]any{"response": map[string]string{"key": key}})
		case r.Method == http.MethodDelete:
			if _, ok := s.vars[key]; !ok {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			delete(s.vars, key)
			jsonStandIn(w, http.StatusOK, map[string]any{"ok": true, "message": "Environment variable deleted"})
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "cloud66", endpoint: standIn.server.URL, binding: "stack-a241-payments", token: token, standIn: standIn})
}

// TestServedLaravelForgeScopedSyncA241: Forge's API — GET
// /orgs/{o}/servers/{s}/sites/{site}/environment returns the whole .env in
// data.attributes.content; PUT {environment} replaces it (202). The stand-in
// keeps the file and checks that lines the sync doesn't own survive.
func TestServedLaravelForgeScopedSyncA241(t *testing.T) {
	const token = "forge-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	const path = "/orgs/acme/servers/101/sites/202/environment"
	var file sync.Mutex
	content := "APP_NAME=Payments\n# managed by hand\nAPP_KEY='base64:handwritten'\n"
	parse := func() map[string]string {
		vars := map[string]string{}
		for _, line := range strings.Split(content, "\n") {
			name, value, ok := strings.Cut(line, "=")
			if !ok || strings.HasPrefix(line, "#") {
				continue
			}
			value = strings.Trim(value, `'`)
			if strings.HasPrefix(value, `"`) {
				value = strings.ReplaceAll(strings.ReplaceAll(strings.Trim(value, `"`), `\"`, `"`), `\\`, `\`)
			}
			vars[name] = value
		}
		return vars
	}
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		if r.URL.Path != path {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		file.Lock()
		defer file.Unlock()
		switch r.Method {
		case http.MethodGet:
			jsonStandIn(w, http.StatusOK, map[string]any{"data": map[string]any{"type": "environment", "attributes": map[string]string{"content": content}}})
		case http.MethodPut:
			var body struct {
				Environment string `json:"environment"`
			}
			if !decodeStandIn(w, r, &body) {
				return
			}
			if !strings.Contains(body.Environment, "# managed by hand\nAPP_KEY='base64:handwritten'") {
				jsonStandIn(w, http.StatusUnprocessableEntity, map[string]string{"message": "the hand-written lines were lost"})
				return
			}
			content = body.Environment
			w.WriteHeader(http.StatusAccepted)
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
		s.mu.Lock()
		s.vars = parse()
		s.mu.Unlock()
	})
	// seed() edits the stand-in's map; mirror it into the file on the next
	// request by writing through the map: the journey seeds and tampers.
	seeding := &forgeSeeder{standIn: standIn, mu: &file, content: &content}
	hostedSyncProof(t, hostedSyncCase{typ: "laravel-forge", endpoint: standIn.server.URL, binding: "org acme server 101 site 202", token: token,
		standIn: standIn, seed: seeding.seed})
}

// forgeSeeder writes a seeded or tampered variable into the stand-in's file.
type forgeSeeder struct {
	standIn *syncStandIn
	mu      *sync.Mutex
	content *string
}

func (f *forgeSeeder) seed(name, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	lines := strings.Split(strings.TrimSuffix(*f.content, "\n"), "\n")
	out := lines[:0]
	for _, line := range lines {
		if !strings.HasPrefix(line, name+"=") {
			out = append(out, line)
		}
	}
	out = append(out, name+"='"+value+"'")
	*f.content = strings.Join(out, "\n") + "\n"
	f.standIn.seed(name, value)
}
