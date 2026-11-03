// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
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
	// path is true for a destination that holds paths, not variable names;
	// pathPrefix is then its folder (default inv241).
	path       bool
	pathPrefix string
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
		folder := c.pathPrefix
		if folder == "" {
			folder = "inv241"
		}
		prefix, transform, dbName, apiName, legacy = folder, "path", folder+"/db_password", folder+"/api_token", folder+"/legacy"
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

// TestServedCircleCIScopedSyncA241: CircleCI API v2 project variables —
// POST /project/{slug}/envvar {name,value}, DELETE by name, GET the list
// with values masked to xxxx plus the last four characters (receipt-only).
func TestServedCircleCIScopedSyncA241(t *testing.T) {
	const token = "circleci-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Circle-Token", token) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/project/gh/acme/payments/envvar")
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "Project not found"})
			return
		}
		name := strings.TrimPrefix(rest, "/")
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case name == "" && r.Method == http.MethodGet:
			items := []map[string]string{}
			for _, k := range sortedKeys(s.vars) {
				v := s.vars[k]
				if len(v) > 4 {
					v = v[len(v)-4:]
				}
				items = append(items, map[string]string{"name": k, "value": "xxxx" + v})
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"items": items, "next_page_token": nil})
		case name == "" && r.Method == http.MethodPost:
			var body struct{ Name, Value string }
			if !decodeStandIn(w, r, &body) {
				return
			}
			s.vars[body.Name] = body.Value
			jsonStandIn(w, http.StatusCreated, map[string]string{"name": body.Name, "value": "xxxx"})
		case r.Method == http.MethodDelete:
			delete(s.vars, name)
			jsonStandIn(w, http.StatusOK, map[string]string{"message": "Environment variable deleted."})
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "circleci", endpoint: standIn.server.URL, binding: "project gh/acme/payments", token: token, standIn: standIn})
}

// TestServedTravisCIScopedSyncA241: Travis CI API v3 — POST
// /repo/{slug}/env_vars with namespaced fields, PATCH and DELETE
// /repo/{slug}/env_var/{id}; a private variable lists without its value.
func TestServedTravisCIScopedSyncA241(t *testing.T) {
	const token = "travis-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	ids := map[string]string{}
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "token "+token) || !standInAuth(w, r, "Travis-API-Version", "3") {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.EscapedPath(), "/repo/acme%2Fpayments")
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"@type": "error", "error_type": "not_found"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
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
		case rest == "/env_vars" && r.Method == http.MethodGet:
			list := []map[string]any{}
			for _, k := range sortedKeys(s.vars) {
				list = append(list, map[string]any{"id": ids[k], "name": k, "public": false})
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"env_vars": list})
		case rest == "/env_vars" && r.Method == http.MethodPost:
			var body map[string]any
			if !decodeStandIn(w, r, &body) {
				return
			}
			name, _ := body["env_var.name"].(string)
			value, _ := body["env_var.value"].(string)
			if public, _ := body["env_var.public"].(bool); public || name == "" {
				jsonStandIn(w, http.StatusBadRequest, map[string]string{"@type": "error"})
				return
			}
			ids[name] = "ev-" + strings.ToLower(name)
			s.vars[name] = value
			jsonStandIn(w, http.StatusCreated, map[string]any{"id": ids[name], "name": name, "public": false})
		case strings.HasPrefix(rest, "/env_var/"):
			key := keyOf(strings.TrimPrefix(rest, "/env_var/"))
			if key == "" {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"@type": "error", "error_type": "not_found"})
				return
			}
			switch r.Method {
			case http.MethodPatch:
				var body map[string]any
				if !decodeStandIn(w, r, &body) {
					return
				}
				s.vars[key], _ = body["env_var.value"].(string)
				jsonStandIn(w, http.StatusOK, map[string]any{"id": ids[key], "name": key})
			case http.MethodDelete:
				delete(s.vars, key)
				w.WriteHeader(http.StatusNoContent)
			}
		default:
			jsonStandIn(w, http.StatusNotFound, map[string]string{"@type": "error"})
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "travis-ci", endpoint: standIn.server.URL, binding: "acme/payments", token: token, standIn: standIn})
}

// TestServedBitbucketScopedSyncA241: Bitbucket Cloud repository Pipelines
// variables — POST (409 if the key exists), PUT and DELETE by {uuid}, a
// paged list where a secured variable has no value.
func TestServedBitbucketScopedSyncA241(t *testing.T) {
	const token = "bitbucket-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	const base = "/repositories/acme/payments/pipelines_config/variables"
	uuids := map[string]string{}
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, base)
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]any{"type": "error"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		keyOf := func(uuid string) string {
			for k, v := range uuids {
				if v == uuid {
					if _, live := s.vars[k]; live {
						return k
					}
				}
			}
			return ""
		}
		switch {
		case rest == "" && r.Method == http.MethodGet:
			// One variable per page, so the engine follows the next links.
			keys := sortedKeys(s.vars)
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page < 1 {
				page = 1
			}
			out := map[string]any{"values": []any{}, "pagelen": 1}
			if page <= len(keys) {
				k := keys[page-1]
				out["values"] = []map[string]any{{"uuid": uuids[k], "key": k, "secured": true}}
			}
			if page < len(keys) {
				out["next"] = "https://api.bitbucket.org/2.0" + base + "?pagelen=100&page=" + strconv.Itoa(page+1)
			}
			jsonStandIn(w, http.StatusOK, out)
		case rest == "" && r.Method == http.MethodPost:
			var body struct {
				Key, Value string
				Secured    bool
			}
			if !decodeStandIn(w, r, &body) || !body.Secured {
				return
			}
			if _, exists := s.vars[body.Key]; exists {
				jsonStandIn(w, http.StatusConflict, map[string]any{"type": "error", "error": map[string]string{"message": "A variable with the provided key already exists."}})
				return
			}
			uuids[body.Key] = "{" + strings.ToLower(body.Key) + "-uuid}"
			s.vars[body.Key] = body.Value
			jsonStandIn(w, http.StatusCreated, map[string]any{"uuid": uuids[body.Key], "key": body.Key, "secured": true})
		default:
			key := keyOf(strings.TrimPrefix(rest, "/"))
			if key == "" {
				jsonStandIn(w, http.StatusNotFound, map[string]any{"type": "error"})
				return
			}
			switch r.Method {
			case http.MethodPut:
				var body struct {
					Key, Value string
					Secured    bool
				}
				if !decodeStandIn(w, r, &body) || body.Key != key || !body.Secured {
					return
				}
				s.vars[key] = body.Value
				jsonStandIn(w, http.StatusOK, map[string]any{"uuid": uuids[key], "key": key})
			case http.MethodDelete:
				delete(s.vars, key)
				w.WriteHeader(http.StatusNoContent)
			}
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "bitbucket", endpoint: standIn.server.URL, binding: "workspace acme repository payments", token: token, standIn: standIn})
}

// TestServedTeamCityScopedSyncA241: TeamCity REST — PUT
// /app/rest/projects/id:{id}/parameters/{name} with a password type, DELETE,
// and the list (inherited parameters marked, password values withheld).
func TestServedTeamCityScopedSyncA241(t *testing.T) {
	const token = "teamcity-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.EscapedPath(), "/app/rest/projects/id:Payments/parameters")
		if !ok {
			rest, ok = strings.CutPrefix(r.URL.EscapedPath(), "/app/rest/projects/id%3APayments/parameters")
		}
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "No project found"})
			return
		}
		name := strings.TrimPrefix(rest, "/")
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case name == "" && r.Method == http.MethodGet:
			props := []map[string]any{{"name": "env.INHERITED_FROM_ROOT", "inherited": true, "type": map[string]string{"rawValue": "password"}}}
			for _, k := range sortedKeys(s.vars) {
				props = append(props, map[string]any{"name": k, "type": map[string]string{"rawValue": "password"}})
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"count": len(props), "property": props})
		case r.Method == http.MethodPut:
			var body struct {
				Name, Value string
				Type        struct {
					RawValue string `json:"rawValue"`
				} `json:"type"`
			}
			if !decodeStandIn(w, r, &body) || body.Name != name || body.Type.RawValue != "password" {
				jsonStandIn(w, http.StatusBadRequest, map[string]string{"message": "bad parameter"})
				return
			}
			s.vars[name] = body.Value
			jsonStandIn(w, http.StatusOK, map[string]any{"name": name, "type": map[string]string{"rawValue": "password"}})
		case r.Method == http.MethodDelete:
			if _, ok := s.vars[name]; !ok {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
				return
			}
			delete(s.vars, name)
			w.WriteHeader(http.StatusNoContent)
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "teamcity", endpoint: standIn.server.URL, binding: "project Payments", token: token, standIn: standIn})
}

// TestServedSpaceliftScopedSyncA241: Spacelift GraphQL — apiKeyUser trades
// the API key for a JWT; contextConfigAdd and contextConfigDelete manage
// write-only environment variables; context(id){config} lists them.
func TestServedSpaceliftScopedSyncA241(t *testing.T) {
	const keyID, keySecret, jwt = "01A241KEYID", "spacelift-a241-secret", "spacelift-a241-jwt" // #nosec G101 -- fabricated fixture credentials; no value is real (CWE-798)
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if r.Method != http.MethodPost || !decodeStandIn(w, r, &req) {
			return
		}
		if strings.Contains(req.Query, "apiKeyUser(") {
			if req.Variables["id"] != keyID || req.Variables["secret"] != keySecret || r.Header.Get("Authorization") != "" {
				jsonStandIn(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "unauthorized"}}})
				return
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"data": map[string]any{"apiKeyUser": map[string]string{"jwt": jwt}}})
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+jwt {
			jsonStandIn(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "unauthorized"}}})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case strings.Contains(req.Query, "contextConfigAdd("):
			config, _ := req.Variables["config"].(map[string]any)
			id, _ := config["id"].(string)
			value, _ := config["value"].(string)
			if req.Variables["context"] != "payments-env" || config["type"] != "ENVIRONMENT_VARIABLE" || config["writeOnly"] != true {
				jsonStandIn(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "bad config"}}})
				return
			}
			if _, exists := s.vars[id]; exists {
				jsonStandIn(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "already exists"}}})
				return
			}
			s.vars[id] = value
			jsonStandIn(w, http.StatusOK, map[string]any{"data": map[string]any{"contextConfigAdd": map[string]string{"id": id}}})
		case strings.Contains(req.Query, "contextConfigDelete("):
			id, _ := req.Variables["id"].(string)
			delete(s.vars, id)
			jsonStandIn(w, http.StatusOK, map[string]any{"data": map[string]any{"contextConfigDelete": map[string]string{"id": id}}})
		case strings.Contains(req.Query, "context(id:"):
			config := []map[string]any{{"id": "/mnt/workspace/kubeconfig", "type": "FILE_MOUNT"}}
			for _, k := range sortedKeys(s.vars) {
				config = append(config, map[string]any{"id": k, "type": "ENVIRONMENT_VARIABLE", "writeOnly": true, "value": nil})
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"data": map[string]any{"context": map[string]any{"config": config}}})
		default:
			jsonStandIn(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "unknown operation"}}})
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "spacelift", endpoint: standIn.server.URL, binding: "context payments-env", username: keyID, token: keySecret, standIn: standIn})
}

// TestServedHumanitecScopedSyncA241: Humanitec shared app values — POST
// (409 if present), PUT and DELETE by key, and the list with a secret's
// value empty.
func TestServedHumanitecScopedSyncA241(t *testing.T) {
	const token = "humanitec-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/orgs/acme/apps/payments/values")
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		key := strings.TrimPrefix(rest, "/")
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case key == "" && r.Method == http.MethodGet:
			list := []map[string]any{}
			for _, k := range sortedKeys(s.vars) {
				list = append(list, map[string]any{"key": k, "value": "", "is_secret": true, "description": "managed by trstctl"})
			}
			jsonStandIn(w, http.StatusOK, list)
		case key == "" && r.Method == http.MethodPost:
			var body struct {
				Key, Value, Description string
				IsSecret                bool `json:"is_secret"`
			}
			if !decodeStandIn(w, r, &body) || !body.IsSecret {
				return
			}
			if _, exists := s.vars[body.Key]; exists {
				jsonStandIn(w, http.StatusConflict, map[string]string{"error": "Shared Value already exists."})
				return
			}
			s.vars[body.Key] = body.Value
			jsonStandIn(w, http.StatusCreated, map[string]any{"key": body.Key, "is_secret": true})
		case key == "" && r.Method == http.MethodDelete:
			t.Error("the target deleted every value in the app")
			jsonStandIn(w, http.StatusNoContent, nil)
		case r.Method == http.MethodPut:
			var body struct{ Value, Description string }
			if !decodeStandIn(w, r, &body) {
				return
			}
			if _, exists := s.vars[key]; !exists {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"error": "Shared Value does not exist."})
				return
			}
			s.vars[key] = body.Value
			jsonStandIn(w, http.StatusOK, map[string]any{"key": key})
		case r.Method == http.MethodDelete:
			if _, exists := s.vars[key]; !exists {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"error": "Shared Value does not exist."})
				return
			}
			delete(s.vars, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "humanitec", endpoint: standIn.server.URL, binding: "org acme app payments", token: token, standIn: standIn})
}

// TestServedRundeckScopedSyncA241: Rundeck Key Storage — POST creates and
// PUT modifies a password key (application/x-rundeck-data-password, the
// value as the body), DELETE removes it, and a directory GET lists its
// resources; password contents are never returned. Keys are paths.
func TestServedRundeckScopedSyncA241(t *testing.T) {
	const token = "rundeck-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	const base = "/api/41/storage/keys/project/payments"
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "X-Rundeck-Auth-Token", token) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, base)
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.Method == http.MethodGet && strings.HasSuffix(rest, "/") {
			dir := strings.Trim(rest, "/")
			seen := map[string]string{}
			for k := range s.vars {
				rel := k
				if dir != "" {
					var inside bool
					if rel, inside = strings.CutPrefix(k, dir+"/"); !inside {
						continue
					}
				}
				head, _, nested := strings.Cut(rel, "/")
				if nested {
					seen[head] = "directory"
				} else {
					seen[head] = "file"
				}
			}
			if len(seen) == 0 && dir != "" {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
				return
			}
			resources := []map[string]any{}
			for _, name := range sortedKeys(seen) {
				item := map[string]any{"name": name, "type": seen[name]}
				if seen[name] == "file" {
					item["meta"] = map[string]string{"Rundeck-key-type": "password", "Rundeck-content-type": "application/x-rundeck-data-password"}
				}
				resources = append(resources, item)
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"type": "directory", "resources": resources})
			return
		}
		key := strings.TrimPrefix(rest, "/")
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			if r.Header.Get("Content-Type") != "application/x-rundeck-data-password" {
				jsonStandIn(w, http.StatusBadRequest, map[string]string{"message": "content type"})
				return
			}
			_, exists := s.vars[key]
			if (r.Method == http.MethodPut && !exists) || (r.Method == http.MethodPost && exists) {
				status := http.StatusNotFound
				if exists {
					status = http.StatusConflict
				}
				jsonStandIn(w, status, map[string]string{"message": "no"})
				return
			}
			body := new(strings.Builder)
			_, _ = io.Copy(body, r.Body)
			s.vars[key] = body.String()
			jsonStandIn(w, http.StatusCreated, map[string]any{"path": "keys/project/payments/" + key, "type": "file"})
		case http.MethodDelete:
			if _, exists := s.vars[key]; !exists {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
				return
			}
			delete(s.vars, key)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			jsonStandIn(w, http.StatusForbidden, map[string]string{"message": "Retrieving private key or password file contents is not allowed"})
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "rundeck", endpoint: standIn.server.URL, binding: "folder keys/project/payments", token: token, standIn: standIn, path: true})
}

// TestServedChecklyScopedSyncA241: Checkly environment variables — POST
// (409 if present), PUT and DELETE by key, a paged list where a secret's
// value is null; every call names the account.
func TestServedChecklyScopedSyncA241(t *testing.T) {
	const token = "checkly-a241-key" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	const account = "cccccccc-dddd-4eee-8fff-000000000000"
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) || !standInAuth(w, r, "X-Checkly-Account", account) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/v1/variables")
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		key := strings.TrimPrefix(rest, "/")
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case key == "" && r.Method == http.MethodGet:
			keys := sortedKeys(s.vars)
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			list := []map[string]any{}
			for i, k := range keys {
				if i >= (page-1)*limit && i < page*limit {
					list = append(list, map[string]any{"key": k, "value": nil, "locked": false, "secret": true})
				}
			}
			jsonStandIn(w, http.StatusOK, list)
		case key == "" && r.Method == http.MethodPost:
			var body struct {
				Key, Value string
				Secret     bool
			}
			if !decodeStandIn(w, r, &body) || !body.Secret {
				return
			}
			if _, exists := s.vars[body.Key]; exists {
				jsonStandIn(w, http.StatusConflict, map[string]string{"message": "exists"})
				return
			}
			s.vars[body.Key] = body.Value
			jsonStandIn(w, http.StatusCreated, map[string]any{"key": body.Key, "secret": true})
		case r.Method == http.MethodPut:
			var body struct {
				Value  string
				Secret bool
			}
			if !decodeStandIn(w, r, &body) || !body.Secret {
				return
			}
			if _, exists := s.vars[key]; !exists {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
				return
			}
			s.vars[key] = body.Value
			jsonStandIn(w, http.StatusOK, map[string]any{"key": key})
		case r.Method == http.MethodDelete:
			if _, exists := s.vars[key]; !exists {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
				return
			}
			delete(s.vars, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "checkly", endpoint: standIn.server.URL, binding: "account " + account, token: token, standIn: standIn})
}

// TestServedWindmillScopedSyncA241: Windmill's workspace variables API —
// POST /w/{ws}/variables/create and /update/{path}, GET /get/{path} (404
// when absent) and /get_value/{path}, DELETE /delete/{path}, a paged list.
// Keys are paths (f/<folder>/<name>).
func TestServedWindmillScopedSyncA241(t *testing.T) {
	const token = "windmill-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/w/payments/variables/")
		if !ok {
			jsonStandIn(w, http.StatusNotFound, "not found")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		op, path, _ := strings.Cut(rest, "/")
		switch {
		case op == "list" && r.Method == http.MethodGet:
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			list := []map[string]any{}
			if page <= 1 {
				for _, k := range sortedKeys(s.vars) {
					list = append(list, map[string]any{"path": k, "is_secret": true, "workspace_id": "payments"})
				}
			}
			jsonStandIn(w, http.StatusOK, list)
		case op == "create" && r.Method == http.MethodPost:
			var body struct {
				Path, Value, Description string
				IsSecret                 bool `json:"is_secret"`
			}
			if !decodeStandIn(w, r, &body) || !body.IsSecret {
				return
			}
			if _, exists := s.vars[body.Path]; exists {
				jsonStandIn(w, http.StatusBadRequest, "already exists")
				return
			}
			s.vars[body.Path] = body.Value
			jsonStandIn(w, http.StatusCreated, body.Path)
		case op == "update" && r.Method == http.MethodPost:
			var body struct{ Value string }
			if !decodeStandIn(w, r, &body) {
				return
			}
			if _, exists := s.vars[path]; !exists {
				jsonStandIn(w, http.StatusNotFound, "not found")
				return
			}
			s.vars[path] = body.Value
			jsonStandIn(w, http.StatusOK, path)
		case op == "get" && r.Method == http.MethodGet:
			if _, exists := s.vars[path]; !exists || r.URL.Query().Get("decrypt_secret") != "false" {
				jsonStandIn(w, http.StatusNotFound, "not found")
				return
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"path": path, "is_secret": true})
		case op == "get_value" && r.Method == http.MethodGet:
			v, exists := s.vars[path]
			if !exists {
				jsonStandIn(w, http.StatusNotFound, "not found")
				return
			}
			jsonStandIn(w, http.StatusOK, v)
		case op == "delete" && r.Method == http.MethodDelete:
			if _, exists := s.vars[path]; !exists {
				jsonStandIn(w, http.StatusNotFound, "not found")
				return
			}
			delete(s.vars, path)
			jsonStandIn(w, http.StatusOK, path)
		default:
			jsonStandIn(w, http.StatusNotFound, "not found")
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "windmill", endpoint: standIn.server.URL, binding: "workspace payments", token: token, standIn: standIn,
		path: true, pathPrefix: "f/inv241"})
}

// TestServedZabbixScopedSyncA241: the Zabbix 7.0 JSON-RPC API —
// usermacro.get/createglobal/updateglobal/deleteglobal with a Bearer token;
// a secret-text macro's value is never returned (receipt-only).
func TestServedZabbixScopedSyncA241(t *testing.T) {
	const token = "zabbix-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	ids := map[string]string{}
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) || r.Header.Get("Content-Type") != "application/json-rpc" {
			jsonStandIn(w, http.StatusUnauthorized, nil)
			return
		}
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
			ID      int             `json:"id"`
		}
		if !decodeStandIn(w, r, &req) || req.JSONRPC != "2.0" {
			return
		}
		reply := func(result any) {
			jsonStandIn(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "result": result, "id": req.ID})
		}
		fail := func() {
			jsonStandIn(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": -32602, "message": "Invalid params."}, "id": req.ID})
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		name := func(macro string) string {
			return strings.TrimSuffix(strings.TrimPrefix(macro, "{$"), "}")
		}
		switch req.Method {
		case "usermacro.get":
			list := []map[string]string{}
			for _, k := range sortedKeys(s.vars) {
				list = append(list, map[string]string{"globalmacroid": ids[k], "macro": "{$" + k + "}"})
			}
			reply(list)
		case "usermacro.createglobal":
			var p struct {
				Macro, Value string
				Type         int
			}
			if json.Unmarshal(req.Params, &p) != nil || p.Type != 1 {
				fail()
				return
			}
			k := name(p.Macro)
			if _, exists := s.vars[k]; exists {
				fail()
				return
			}
			ids[k] = strconv.Itoa(len(ids) + 100)
			s.vars[k] = p.Value
			reply(map[string][]string{"globalmacroids": {ids[k]}})
		case "usermacro.updateglobal":
			var p struct {
				GlobalMacroID string `json:"globalmacroid"`
				Value         string
				Type          int
			}
			if json.Unmarshal(req.Params, &p) != nil || p.Type != 1 {
				fail()
				return
			}
			for k, id := range ids {
				if id == p.GlobalMacroID {
					if _, live := s.vars[k]; live {
						s.vars[k] = p.Value
						reply(map[string][]string{"globalmacroids": {id}})
						return
					}
				}
			}
			fail()
		case "usermacro.deleteglobal":
			var del []string
			if json.Unmarshal(req.Params, &del) != nil {
				fail()
				return
			}
			for _, id := range del {
				for k, v := range ids {
					if v == id {
						delete(s.vars, k)
					}
				}
			}
			reply(map[string][]string{"globalmacroids": del})
		default:
			fail()
		}
	})
	// The journey's keys are upper-case macro names, as Zabbix requires; the
	// stand-in holds them without the {$ } decoration.
	hostedSyncProof(t, hostedSyncCase{typ: "zabbix", endpoint: standIn.server.URL + "/api_jsonrpc.php", binding: "global", token: token, standIn: standIn})
}

// TestServedPortainerScopedSyncA241: Portainer's stack API — GET
// /api/stacks/{id} (Env) and /file (StackFileContent), PUT
// /api/stacks/{id}?endpointId= with the compose file, Env and Prune.
func TestServedPortainerScopedSyncA241(t *testing.T) {
	const token = "portainer-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	const compose = "services:\n  web:\n    image: nginx:stable\n"
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "X-API-Key", token) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		env := func() []map[string]string {
			out := []map[string]string{}
			for _, k := range sortedKeys(s.vars) {
				out = append(out, map[string]string{"name": k, "value": s.vars[k]})
			}
			return out
		}
		switch {
		case r.URL.Path == "/api/stacks/7" && r.Method == http.MethodGet:
			jsonStandIn(w, http.StatusOK, map[string]any{"Id": 7, "Name": "payments", "EndpointId": 3, "Env": env()})
		case r.URL.Path == "/api/stacks/7/file" && r.Method == http.MethodGet:
			jsonStandIn(w, http.StatusOK, map[string]string{"StackFileContent": compose})
		case r.URL.Path == "/api/stacks/7" && r.Method == http.MethodPut:
			var body struct {
				StackFileContent string
				Env              []struct{ Name, Value string }
				Prune            bool
			}
			if r.URL.Query().Get("endpointId") != "3" || !decodeStandIn(w, r, &body) || body.StackFileContent != compose || body.Prune {
				jsonStandIn(w, http.StatusBadRequest, map[string]string{"message": "bad stack update"})
				return
			}
			next := map[string]string{}
			for _, e := range body.Env {
				next[e.Name] = e.Value
			}
			s.vars = next
			jsonStandIn(w, http.StatusOK, map[string]any{"Id": 7, "Env": env()})
		default:
			jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "portainer", endpoint: standIn.server.URL, binding: "stack 7 environment 3", token: token, standIn: standIn})
}

// TestServedDevinScopedSyncA241: Devin's v3 organization secrets — POST
// creates (no update: a change deletes and creates), DELETE by secret_id,
// a cursor-paged list without values.
func TestServedDevinScopedSyncA241(t *testing.T) {
	const token = "cog_a241_token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	ids := map[string]string{}
	seq := 0
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/v3/organizations/org-acme/secrets")
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"detail": "not found"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case rest == "" && r.Method == http.MethodGet:
			items := []map[string]any{}
			for _, k := range sortedKeys(s.vars) {
				items = append(items, map[string]any{"secret_id": ids[k], "key": k, "secret_type": "key-value", "is_sensitive": true})
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"items": items, "has_next_page": false, "end_cursor": nil, "total": len(items)})
		case rest == "" && r.Method == http.MethodPost:
			var body struct {
				Type, Key, Value string
				IsSensitive      bool `json:"is_sensitive"`
			}
			if !decodeStandIn(w, r, &body) || body.Type != "key-value" || !body.IsSensitive {
				return
			}
			if _, exists := s.vars[body.Key]; exists {
				jsonStandIn(w, http.StatusConflict, map[string]string{"detail": "conflict"})
				return
			}
			seq++
			ids[body.Key] = "secret-" + strconv.Itoa(seq)
			s.vars[body.Key] = body.Value
			jsonStandIn(w, http.StatusOK, map[string]any{"secret_id": ids[body.Key], "key": body.Key})
		case r.Method == http.MethodDelete:
			id := strings.TrimPrefix(rest, "/")
			for k, v := range ids {
				if v == id {
					if _, live := s.vars[k]; live {
						delete(s.vars, k)
						jsonStandIn(w, http.StatusOK, map[string]any{"secret_id": id})
						return
					}
				}
			}
			jsonStandIn(w, http.StatusNotFound, map[string]string{"detail": "not found"})
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "devin", endpoint: standIn.server.URL, binding: "org org-acme", token: token, standIn: standIn})
}

// TestServedDaytonaScopedSyncA241: Daytona organization secrets — POST
// /secret {name,value}, PATCH /secret/{id} {value}, DELETE, and the
// cursor-paged /secret/paginated list without values.
func TestServedDaytonaScopedSyncA241(t *testing.T) {
	const token = "daytona-a241-key" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	const org = "dddddddd-eeee-4fff-8000-111111111111"
	ids := map[string]string{}
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) || !standInAuth(w, r, "X-Daytona-Organization-ID", org) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case r.URL.Path == "/secret/paginated" && r.Method == http.MethodGet:
			items := []map[string]any{}
			for _, k := range sortedKeys(s.vars) {
				items = append(items, map[string]any{"id": ids[k], "name": k, "placeholder": "dtn_secret_x"})
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"items": items, "total": len(items), "nextCursor": nil})
		case r.URL.Path == "/secret" && r.Method == http.MethodPost:
			var body struct{ Name, Value, Description string }
			if !decodeStandIn(w, r, &body) {
				return
			}
			if _, exists := s.vars[body.Name]; exists {
				jsonStandIn(w, http.StatusConflict, map[string]string{"message": "exists"})
				return
			}
			ids[body.Name] = "sec-" + strings.ToLower(body.Name)
			s.vars[body.Name] = body.Value
			jsonStandIn(w, http.StatusCreated, map[string]any{"id": ids[body.Name], "name": body.Name})
		case strings.HasPrefix(r.URL.Path, "/secret/"):
			id := strings.TrimPrefix(r.URL.Path, "/secret/")
			key := ""
			for k, v := range ids {
				if _, live := s.vars[k]; live && v == id {
					key = k
				}
			}
			if key == "" {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
				return
			}
			switch r.Method {
			case http.MethodPatch:
				var body struct{ Value string }
				if !decodeStandIn(w, r, &body) {
					return
				}
				s.vars[key] = body.Value
				jsonStandIn(w, http.StatusOK, map[string]any{"id": id, "name": key})
			case http.MethodDelete:
				delete(s.vars, key)
				w.WriteHeader(http.StatusNoContent)
			}
		default:
			jsonStandIn(w, http.StatusNotFound, map[string]string{"message": "not found"})
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "daytona", endpoint: standIn.server.URL, binding: "organization " + org, token: token, standIn: standIn})
}

// TestServedOnaScopedSyncA241: Ona's SecretService over Connect RPC —
// CreateSecret, UpdateSecretValue, DeleteSecret and ListSecrets (metadata
// only), each a JSON POST, scoped to an organization.
func TestServedOnaScopedSyncA241(t *testing.T) {
	const token = "ona-a241-token" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	const org = "eeeeeeee-ffff-4000-8111-222222222222"
	ids := map[string]string{}
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) || r.Method != http.MethodPost {
			return
		}
		method, ok := strings.CutPrefix(r.URL.Path, "/gitpod.v1.SecretService/")
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"code": "not_found"})
			return
		}
		var req map[string]any
		if !decodeStandIn(w, r, &req) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		keyOf := func(id string) string {
			for k, v := range ids {
				if _, live := s.vars[k]; live && v == id {
					return k
				}
			}
			return ""
		}
		switch method {
		case "ListSecrets":
			filter, _ := req["filter"].(map[string]any)
			scope, _ := filter["scope"].(map[string]any)
			if scope["organizationId"] != org {
				jsonStandIn(w, http.StatusOK, map[string]any{"secrets": []any{}, "pagination": map[string]string{"nextToken": ""}})
				return
			}
			list := []map[string]any{}
			for _, k := range sortedKeys(s.vars) {
				list = append(list, map[string]any{"id": ids[k], "name": k, "environmentVariable": true})
			}
			jsonStandIn(w, http.StatusOK, map[string]any{"secrets": list, "pagination": map[string]string{"nextToken": ""}})
		case "CreateSecret":
			name, _ := req["name"].(string)
			value, _ := req["value"].(string)
			scope, _ := req["scope"].(map[string]any)
			if scope["organizationId"] != org || req["environmentVariable"] != true {
				jsonStandIn(w, http.StatusBadRequest, map[string]string{"code": "invalid_argument"})
				return
			}
			ids[name] = "s-" + strings.ToLower(name)
			s.vars[name] = value
			jsonStandIn(w, http.StatusOK, map[string]any{"secret": map[string]string{"id": ids[name], "name": name}})
		case "UpdateSecretValue":
			id, _ := req["secretId"].(string)
			key := keyOf(id)
			if key == "" {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"code": "not_found"})
				return
			}
			s.vars[key], _ = req["value"].(string)
			jsonStandIn(w, http.StatusOK, map[string]any{})
		case "DeleteSecret":
			id, _ := req["secretId"].(string)
			key := keyOf(id)
			if key == "" {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"code": "not_found"})
				return
			}
			delete(s.vars, key)
			jsonStandIn(w, http.StatusOK, map[string]any{})
		default:
			jsonStandIn(w, http.StatusNotFound, map[string]string{"code": "unimplemented"})
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "ona", endpoint: standIn.server.URL, binding: "organization " + org, token: token, standIn: standIn})
}

// TestServedTriggerDevScopedSyncA241: Trigger.dev's environment variables
// API — POST .../envvars/{env}/import with override upserts, DELETE removes,
// GET lists [{name,value}] and GET .../{name} returns {value}.
func TestServedTriggerDevScopedSyncA241(t *testing.T) {
	const token = "tr_pat_a241" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	standIn := newSyncStandIn(t, func(s *syncStandIn, w http.ResponseWriter, r *http.Request) {
		if !standInAuth(w, r, "Authorization", "Bearer "+token) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/projects/proj_a241payments/envvars/prod")
		if !ok {
			jsonStandIn(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		name := strings.TrimPrefix(rest, "/")
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case name == "" && r.Method == http.MethodGet:
			list := []map[string]string{}
			for _, k := range sortedKeys(s.vars) {
				list = append(list, map[string]string{"name": k, "value": s.vars[k]})
			}
			jsonStandIn(w, http.StatusOK, list)
		case name == "import" && r.Method == http.MethodPost:
			var body struct {
				Variables []struct{ Name, Value string }
				Override  bool
			}
			if !decodeStandIn(w, r, &body) {
				return
			}
			for _, v := range body.Variables {
				if _, exists := s.vars[v.Name]; exists && !body.Override {
					continue
				}
				s.vars[v.Name] = v.Value
			}
			jsonStandIn(w, http.StatusOK, map[string]bool{"success": true})
		case r.Method == http.MethodGet:
			v, exists := s.vars[name]
			if !exists {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			jsonStandIn(w, http.StatusOK, map[string]string{"value": v})
		case r.Method == http.MethodDelete:
			if _, exists := s.vars[name]; !exists {
				jsonStandIn(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			delete(s.vars, name)
			jsonStandIn(w, http.StatusOK, map[string]bool{"success": true})
		default:
			jsonStandIn(w, http.StatusMethodNotAllowed, nil)
		}
	})
	hostedSyncProof(t, hostedSyncCase{typ: "trigger-dev", endpoint: standIn.server.URL, binding: "project proj_a241payments env prod", token: token, standIn: standIn})
}
