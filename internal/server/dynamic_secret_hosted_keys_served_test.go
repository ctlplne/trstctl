// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// The A240 hosted API key stand-ins below follow each vendor's API reference
// (research notes 2026-11-03): request and response shapes, status codes, and
// what the vendor answers for a key that is gone. Each admits only the
// administrator's credential on its management routes and only a live key on
// the route the test uses the key with.

// hostedKeyOf reads field from a credential document.
func hostedKeyOf(field string) func(t *testing.T, credential string) string {
	return func(t *testing.T, credential string) string {
		t.Helper()
		var parsed map[string]any
		if err := json.Unmarshal([]byte(credential), &parsed); err != nil {
			t.Fatalf("the credential is not JSON: %v", err)
		}
		value, _ := parsed[field].(string)
		if value == "" {
			t.Fatalf("the credential carries no %s", field)
		}
		return value
	}
}

// hostedKeyUse calls url with the key in header and reports whether the
// stand-in accepted it.
func hostedKeyUse(url, header, prefix string) func(t *testing.T, key string) bool {
	return func(t *testing.T, key string) bool {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(header, prefix+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
}

func hostedJSONReply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// --- Fireworks AI ---------------------------------------------------------

type servedFireworks struct {
	mu     sync.Mutex
	keys   map[string][3]string // keyId -> user path, displayName, key
	serial int
}

func (f *servedFireworks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/v1/accounts" {
		for _, key := range f.keys {
			if r.Header.Get("Authorization") == "Bearer "+key[2] {
				hostedJSONReply(w, http.StatusOK, map[string]any{"accounts": []any{map[string]string{"name": "accounts/acme"}}})
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Authorization") != "Bearer served-fireworks-admin-key" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user, del := strings.CutSuffix(r.URL.Path, "/apiKeys:delete")
	if !del {
		user = strings.TrimSuffix(r.URL.Path, "/apiKeys")
	}
	if user != "/v1/accounts/acme/users/ci-bot" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch {
	case r.Method == http.MethodPost && del:
		var body struct {
			KeyID string `json:"keyId"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, ok := f.keys[body.KeyID]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.keys, body.KeyID)
		hostedJSONReply(w, http.StatusOK, map[string]any{})
	case r.Method == http.MethodPost:
		var body struct {
			APIKey struct {
				DisplayName string `json:"displayName"`
			} `json:"apiKey"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.APIKey.DisplayName == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.serial++
		id, key := fmt.Sprintf("served-key-%d", f.serial), fmt.Sprintf("fw_served_%04d", f.serial)
		f.keys[id] = [3]string{user, body.APIKey.DisplayName, key}
		hostedJSONReply(w, http.StatusOK, map[string]any{"keyId": id, "displayName": body.APIKey.DisplayName, "key": key})
	case r.Method == http.MethodGet:
		keys := []map[string]string{}
		for id, key := range f.keys {
			keys = append(keys, map[string]string{"keyId": id, "displayName": key[1]})
		}
		hostedJSONReply(w, http.StatusOK, map[string]any{"apiKeys": keys})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// A240 Fireworks AI, against a stand-in of the API: a lease is an API key of
// the bound user that lists accounts until revocation deletes it; a static
// rotation is two-phase.
func TestServedFireworksKeysLeaseAndRotateA240(t *testing.T) {
	vendor := &servedFireworks{keys: map[string][3]string{}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "fireworks-acme", Type: "fireworks", Endpoint: stand.URL,
			APIKeyRef:    writeServedCredentialFile(t, "fireworks-admin", "served-fireworks-admin-key"),
			AllowedRoles: []string{"fireworks/ci"}, RoleBindings: map[string]string{"fireworks/ci": "acme/ci-bot"},
			MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "fireworks/ci", seed: `{"api_key":"issued-outside-trstctl"}`,
		keyOf: hostedKeyOf("api_key"), authenticates: hostedKeyUse(stand.URL+"/v1/accounts", "Authorization", "Bearer "),
		newRefPrefix: "acme:ci-bot/served-key-", leases: true, wantVerifyMode: "authenticated",
	}.run(t)
}

// --- LiteLLM proxy -----------------------------------------------------------

type servedLiteLLM struct {
	mu     sync.Mutex
	keys   map[string][3]string // token hash -> alias, key, models
	serial int
}

func (l *servedLiteLLM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	master := r.Header.Get("Authorization") == "Bearer sk-served-master"
	if r.URL.Path == "/key/info" && r.URL.Query().Get("key") == "" {
		for token, key := range l.keys {
			if r.Header.Get("Authorization") == "Bearer "+key[1] {
				hostedJSONReply(w, http.StatusOK, map[string]any{"key": token, "info": map[string]any{"key_alias": key[0]}})
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !master {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/key/generate":
		var body struct {
			KeyAlias string   `json:"key_alias"`
			Models   []string `json:"models"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.KeyAlias == "" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		l.serial++
		token, key := fmt.Sprintf("%064x", l.serial), fmt.Sprintf("sk-served-%04d", l.serial)
		l.keys[token] = [3]string{body.KeyAlias, key, strings.Join(body.Models, ",")}
		hostedJSONReply(w, http.StatusOK, map[string]any{"key": key, "token": token, "key_alias": body.KeyAlias, "models": body.Models})
	case r.Method == http.MethodGet && r.URL.Path == "/key/list":
		keys := []map[string]string{}
		for token, key := range l.keys {
			if alias := r.URL.Query().Get("key_alias"); alias == "" || alias == key[0] {
				keys = append(keys, map[string]string{"token": token, "key_alias": key[0]})
			}
		}
		hostedJSONReply(w, http.StatusOK, map[string]any{"keys": keys, "total_count": len(keys)})
	case r.Method == http.MethodGet && r.URL.Path == "/key/info":
		key, ok := l.keys[r.URL.Query().Get("key")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		hostedJSONReply(w, http.StatusOK, map[string]any{"key": r.URL.Query().Get("key"), "info": map[string]any{"key_alias": key[0]}})
	case r.Method == http.MethodPost && r.URL.Path == "/key/delete":
		var body struct {
			Keys []string `json:"keys"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Keys) != 1 {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		if _, ok := l.keys[body.Keys[0]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(l.keys, body.Keys[0])
		hostedJSONReply(w, http.StatusOK, map[string]any{"deleted_keys": body.Keys})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// A240 LiteLLM proxy, against a stand-in of its key API: a lease is a virtual
// key limited to the role's models that reads its own details until
// revocation deletes it; a static rotation is two-phase.
func TestServedLiteLLMVirtualKeysLeaseAndRotateA240(t *testing.T) {
	vendor := &servedLiteLLM{keys: map[string][3]string{}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "litellm-proxy", Type: "litellm", Endpoint: stand.URL,
			APIKeyRef:    writeServedCredentialFile(t, "litellm-master", "sk-served-master"),
			AllowedRoles: []string{"litellm/app"}, RoleBindings: map[string]string{"litellm/app": "models openai/gpt-4o,claude-sonnet"},
			MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "litellm/app", seed: `{"api_key":"issued-outside-trstctl"}`,
		keyOf: hostedKeyOf("api_key"), authenticates: hostedKeyUse(stand.URL+"/key/info", "Authorization", "Bearer "),
		newRefPrefix: "models:openai/gpt-4o,claude-sonnet/", leases: true, wantVerifyMode: "authenticated",
	}.run(t)
	vendor.mu.Lock()
	defer vendor.mu.Unlock()
	for _, key := range vendor.keys {
		if key[2] != "openai/gpt-4o,claude-sonnet" {
			t.Fatalf("a key was generated for models %q, want the role's", key[2])
		}
	}
}

// --- Supabase -----------------------------------------------------------------

var servedSupabaseKeyName = regexp.MustCompile(`^[a-z_][a-z0-9_]{3,63}$`)

type servedSupabase struct {
	mu     sync.Mutex
	keys   map[string][3]string // id -> name, type, value
	serial int
}

func (s *servedSupabase) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/rest/v1/" {
		for _, key := range s.keys {
			if r.Header.Get("apikey") == key[2] {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Authorization") != "Bearer sbp_served_access_token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	id, ok := strings.CutPrefix(r.URL.Path, "/v1/projects/abcdefghijklmnopqrst/api-keys")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	id = strings.TrimPrefix(id, "/")
	view := func(id string) map[string]any {
		return map[string]any{"id": id, "name": s.keys[id][0], "type": s.keys[id][1], "api_key": nil}
	}
	switch {
	case r.Method == http.MethodPost && id == "":
		var body struct {
			Type, Name string
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Type != "secret" || !servedSupabaseKeyName.MatchString(body.Name) || r.URL.Query().Get("reveal") != "true" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.serial++
		id := fmt.Sprintf("0b4c5d6e-0000-4000-8000-%012d", s.serial)
		s.keys[id] = [3]string{body.Name, "secret", fmt.Sprintf("sb_secret_served%04d", s.serial)}
		reply := view(id)
		reply["api_key"] = s.keys[id][2]
		hostedJSONReply(w, http.StatusCreated, reply)
	case r.Method == http.MethodGet && id == "":
		keys := []map[string]any{}
		for id := range s.keys {
			keys = append(keys, view(id))
		}
		hostedJSONReply(w, http.StatusOK, keys)
	case r.Method == http.MethodGet || r.Method == http.MethodDelete:
		if _, ok := s.keys[id]; !ok {
			hostedJSONReply(w, http.StatusNotFound, map[string]string{"message": "API key not found for project"})
			return
		}
		reply := view(id)
		if r.Method == http.MethodDelete {
			delete(s.keys, id)
		}
		hostedJSONReply(w, http.StatusOK, reply)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// A240 Supabase, against a stand-in of the Management API: a lease is a secret
// API key the project's data API accepts until revocation deletes it; a static
// rotation is two-phase, verified as not available (Supabase documents no key
// check), and never touches the project's publishable key.
func TestServedSupabaseSecretKeysLeaseAndRotateA240(t *testing.T) {
	vendor := &servedSupabase{keys: map[string][3]string{
		"0b4c5d6e-0000-4000-8000-publishable0": {"default", "publishable", "sb_publishable_served"},
	}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "supabase-project", Type: "supabase", Endpoint: stand.URL,
			APIKeyRef:    writeServedCredentialFile(t, "supabase-token", "sbp_served_access_token"),
			AllowedRoles: []string{"supabase/worker"}, RoleBindings: map[string]string{"supabase/worker": "abcdefghijklmnopqrst"},
			MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "supabase/worker", seed: `{"api_key":"issued-outside-trstctl"}`,
		keyOf: hostedKeyOf("api_key"), authenticates: hostedKeyUse(stand.URL+"/rest/v1/", "apikey", ""),
		newRefPrefix: "abcdefghijklmnopqrst/0b4c5d6e-", leases: true, wantVerifyMode: "not_available",
	}.run(t)
	vendor.mu.Lock()
	defer vendor.mu.Unlock()
	if _, ok := vendor.keys["0b4c5d6e-0000-4000-8000-publishable0"]; !ok {
		t.Fatal("the project's publishable key was deleted")
	}
}

// --- Convex ---------------------------------------------------------------------

type servedConvex struct {
	mu      sync.Mutex
	keys    map[string][2]string // name -> key, actions
	serial  int
	deletes int
}

func (c *servedConvex) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.URL.Path == "/api/v1/deployment_info" {
		for _, key := range c.keys {
			if r.Header.Get("Authorization") == "Convex "+key[0] {
				hostedJSONReply(w, http.StatusOK, map[string]string{"deploymentName": "happy-animal-123"})
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Authorization") != "Bearer served-convex-team-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/v1/deployments/happy-animal-123/create_deploy_key":
		var body struct {
			Name           string   `json:"name"`
			AllowedActions []string `json:"allowedActions"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil || body.Name == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, taken := c.keys[body.Name]; taken {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.serial++
		key := fmt.Sprintf("dev:happy-animal-123|served%04d", c.serial)
		c.keys[body.Name] = [2]string{key, strings.Join(body.AllowedActions, ",")}
		hostedJSONReply(w, http.StatusOK, map[string]string{"deployKey": key})
	case "/v1/deployments/happy-animal-123/list_deploy_keys":
		keys := []map[string]any{}
		serial := 0
		for name, key := range c.keys {
			serial++
			keys = append(keys, map[string]any{"id": serial, "name": name, "creationTime": 1, "allowedActions": strings.Split(key[1], ",")})
		}
		hostedJSONReply(w, http.StatusOK, keys)
	case "/v1/deployments/happy-animal-123/delete_deploy_key":
		var body struct {
			ID string `json:"id"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, ok := c.keys[body.ID]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		c.deletes++
		delete(c.keys, body.ID)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// A240 Convex, against a stand-in of the Platform API: a lease is a deploy key
// limited to the role's actions that the deployment accepts until revocation
// deletes it by name; a static rotation is two-phase and verified as not
// available (only the deployment checks a deploy key).
func TestServedConvexDeployKeysLeaseAndRotateA240(t *testing.T) {
	vendor := &servedConvex{keys: map[string][2]string{}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "convex-team", Type: "convex", Endpoint: stand.URL + "/v1",
			APIKeyRef:    writeServedCredentialFile(t, "convex-token", "served-convex-team-token"),
			AllowedRoles: []string{"convex/ci"}, RoleBindings: map[string]string{"convex/ci": "happy-animal-123 deployment:deploy,deployment:env:view"},
			MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "convex/ci", seed: `{"deploy_key":"issued-outside-trstctl"}`,
		keyOf: hostedKeyOf("deploy_key"), authenticates: hostedKeyUse(stand.URL+"/api/v1/deployment_info", "Authorization", "Convex "),
		newRefPrefix: "happy-animal-123:deployment:deploy,deployment:env:view/trstctl-", leases: true, wantVerifyMode: "not_available",
	}.run(t)
	vendor.mu.Lock()
	defer vendor.mu.Unlock()
	for name, key := range vendor.keys {
		if key[1] != "deployment:deploy,deployment:env:view" {
			t.Fatalf("deploy key %s was created with actions %q, want the role's", name, key[1])
		}
	}
}

// --- dbt platform -----------------------------------------------------------------

type servedDBT struct {
	mu     sync.Mutex
	tokens map[int]map[string]any // id -> name, state, token_string, permission_grants
	serial int
}

func (d *servedDBT) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.URL.Path == "/api/v3/accounts/" && r.Method == http.MethodGet {
		for _, token := range d.tokens {
			if token["state"] == 1 && r.Header.Get("Authorization") == "Bearer "+token["token_string"].(string) {
				hostedJSONReply(w, http.StatusOK, map[string]any{"data": []any{map[string]any{"id": 70403}}})
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Authorization") != "Bearer served-dbt-admin-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/v3/accounts/70403/service-tokens/")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	view := func(id int) map[string]any {
		return map[string]any{"id": id, "name": d.tokens[id]["name"], "state": d.tokens[id]["state"]}
	}
	switch {
	case r.Method == http.MethodPost && rest == "":
		var body struct {
			Name             string           `json:"name"`
			PermissionGrants []map[string]any `json:"permission_grants"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name == "" || len(body.PermissionGrants) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		d.serial++
		d.tokens[d.serial] = map[string]any{"name": body.Name, "state": 1, "token_string": fmt.Sprintf("dbtc_served%04d", d.serial), "permission_grants": body.PermissionGrants}
		reply := view(d.serial)
		reply["token_string"] = d.tokens[d.serial]["token_string"]
		hostedJSONReply(w, http.StatusOK, map[string]any{"status": map[string]any{"code": 200, "is_success": true}, "data": reply})
	case r.Method == http.MethodGet && rest == "":
		tokens := []map[string]any{}
		for id := range d.tokens {
			tokens = append(tokens, view(id))
		}
		hostedJSONReply(w, http.StatusOK, map[string]any{"data": tokens})
	case r.Method == http.MethodGet || r.Method == http.MethodDelete:
		id, err := strconv.Atoi(strings.TrimSuffix(rest, "/"))
		token, found := d.tokens[id]
		if err != nil || !found || (r.Method == http.MethodDelete && token["state"] != 1) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet {
			hostedJSONReply(w, http.StatusOK, map[string]any{"data": view(id)})
			return
		}
		// A deleted token stays listed with state 2.
		token["state"] = 2
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// A240 dbt platform, against a stand-in of the v3 API: a lease is a service
// token with the role's one grant that lists accounts until revocation deletes
// it (a deleted token stays listed with state 2); a static rotation is
// two-phase.
func TestServedDBTServiceTokensLeaseAndRotateA240(t *testing.T) {
	vendor := &servedDBT{tokens: map[int]map[string]any{}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "dbt-account", Type: "dbt", Endpoint: stand.URL,
			APIKeyRef:    writeServedCredentialFile(t, "dbt-admin", "served-dbt-admin-token"),
			AllowedRoles: []string{"dbt/jobs"}, RoleBindings: map[string]string{"dbt/jobs": "70403 job_runner project 12"},
			MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "dbt/jobs", seed: `{"token":"issued-outside-trstctl"}`,
		keyOf: hostedKeyOf("token"), authenticates: hostedKeyUse(stand.URL+"/api/v3/accounts/", "Authorization", "Bearer "),
		newRefPrefix: "70403:job_runner:12/", leases: true, wantVerifyMode: "authenticated",
	}.run(t)
	vendor.mu.Lock()
	defer vendor.mu.Unlock()
	for id, token := range vendor.tokens {
		grants := token["permission_grants"].([]map[string]any)
		if grants[0]["permission_set"] != "job_runner" || fmt.Sprint(grants[0]["project_id"]) != "12" {
			t.Fatalf("token %d was created with grants %v, want the role's", id, grants)
		}
	}
}

// --- Cloudflare API tokens and R2 -------------------------------------------------

const (
	servedCloudflareTemplate = "0123456789abcdef0123456789abcdef"
	servedCloudflareAccount  = "fedcba9876543210fedcba9876543210"
)

type servedCloudflare struct {
	mu       sync.Mutex
	tokens   map[string][3]string // id -> base path, name, value
	policies map[string]string    // id -> the policies it was created with
	serial   int
}

func (c *servedCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	reply := func(status int, result any) {
		hostedJSONReply(w, status, map[string]any{"success": status == http.StatusOK, "errors": []any{}, "result": result,
			"result_info": map[string]int{"page": 1, "per_page": 50, "total_pages": 1}})
	}
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	base := "/user/tokens"
	if strings.HasPrefix(path, "/accounts/"+servedCloudflareAccount+"/tokens") {
		base = "/accounts/" + servedCloudflareAccount + "/tokens"
	}
	rest, ok := strings.CutPrefix(path, base)
	if !ok {
		reply(http.StatusNotFound, nil)
		return
	}
	if rest == "/verify" {
		for id, token := range c.tokens {
			if token[0] == base && r.Header.Get("Authorization") == "Bearer "+token[2] {
				reply(http.StatusOK, map[string]string{"id": id, "status": "active"})
				return
			}
		}
		reply(http.StatusUnauthorized, nil)
		return
	}
	if r.Header.Get("Authorization") != "Bearer served-cloudflare-admin-token" {
		reply(http.StatusForbidden, nil)
		return
	}
	id := strings.TrimPrefix(rest, "/")
	switch {
	case r.Method == http.MethodGet && id == servedCloudflareTemplate:
		reply(http.StatusOK, map[string]any{"id": id, "name": "ci deploys (template)", "status": "active",
			"policies": []any{map[string]any{"id": "f267e341f3dd4697bd3b9f71dd96247f", "effect": "allow",
				"permission_groups": []any{map[string]any{"id": "c8fed203ed3043cba015a93ad1616f1f", "name": "Zone Read"}},
				"resources":         map[string]string{"com.cloudflare.api.account.zone.eb78d65290b24279ba6f44721b3ea3c4": "*"}}},
			"condition": map[string]any{"request_ip": map[string]any{"in": []string{"192.0.2.0/24"}}}})
	case r.Method == http.MethodPost && id == "":
		var body struct {
			Name      string            `json:"name"`
			Policies  []json.RawMessage `json:"policies"`
			Condition json.RawMessage   `json:"condition"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name == "" || len(body.Name) > 120 || len(body.Policies) == 0 {
			reply(http.StatusBadRequest, nil)
			return
		}
		c.serial++
		newID := fmt.Sprintf("%032x", c.serial)
		c.tokens[newID] = [3]string{base, body.Name, fmt.Sprintf("served-cf-token-%04d", c.serial)}
		c.policies[newID] = string(body.Policies[0]) + " " + string(body.Condition)
		reply(http.StatusOK, map[string]any{"id": newID, "name": body.Name, "value": c.tokens[newID][2]})
	case r.Method == http.MethodGet && id == "":
		tokens := []map[string]string{}
		for tid, token := range c.tokens {
			if token[0] == base {
				tokens = append(tokens, map[string]string{"id": tid, "name": token[1]})
			}
		}
		reply(http.StatusOK, tokens)
	case r.Method == http.MethodGet || r.Method == http.MethodDelete:
		token, found := c.tokens[id]
		if !found || token[0] != base {
			reply(http.StatusNotFound, nil)
			return
		}
		if r.Method == http.MethodDelete {
			delete(c.tokens, id)
		}
		reply(http.StatusOK, map[string]string{"id": id, "name": token[1]})
	default:
		reply(http.StatusMethodNotAllowed, nil)
	}
}

// assertCopiedTemplate checks each live token copied the template's policy by
// its permission group ID only (never the template's own policy ID or group
// name) and its condition.
func (c *servedCloudflare) assertCopiedTemplate(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, policy := range c.policies {
		if _, live := c.tokens[id]; !live {
			continue
		}
		if !strings.Contains(policy, `"c8fed203ed3043cba015a93ad1616f1f"`) || !strings.Contains(policy, "192.0.2.0/24") ||
			strings.Contains(policy, "f267e341f3dd4697bd3b9f71dd96247f") || strings.Contains(policy, "Zone Read") {
			t.Fatalf("token %s did not copy exactly the template's policy and condition: %s", id, policy)
		}
	}
}

// A240 Cloudflare API tokens, against a stand-in of the API: a lease is a
// copy of the template token that Cloudflare's verification route accepts
// until revocation deletes it; a static rotation is two-phase.
func TestServedCloudflareTokensLeaseAndRotateA240(t *testing.T) {
	vendor := &servedCloudflare{tokens: map[string][3]string{}, policies: map[string]string{}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "cloudflare-user", Type: "cloudflare", Endpoint: stand.URL + "/client/v4",
			APIKeyRef:    writeServedCredentialFile(t, "cloudflare-admin", "served-cloudflare-admin-token"),
			AllowedRoles: []string{"cloudflare/deploys"}, RoleBindings: map[string]string{"cloudflare/deploys": "template " + servedCloudflareTemplate},
			MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "cloudflare/deploys", seed: `{"api_token":"issued-outside-trstctl"}`,
		keyOf: hostedKeyOf("api_token"), authenticates: hostedKeyUse(stand.URL+"/client/v4/user/tokens/verify", "Authorization", "Bearer "),
		newRefPrefix: "user:" + servedCloudflareTemplate + "/", leases: true, wantVerifyMode: "authenticated",
	}.run(t)
	vendor.assertCopiedTemplate(t)
}

// A240 Cloudflare R2, against a stand-in of the API: a lease is an S3 pair
// derived from a new account token (access key ID = token ID, secret access
// key = SHA-256 of its value) that works until revocation deletes the token;
// a static rotation is two-phase and verified as not available.
func TestServedCloudflareR2KeysLeaseAndRotateA240(t *testing.T) {
	vendor := &servedCloudflare{tokens: map[string][3]string{}, policies: map[string]string{}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	// The S3 side of the stand-in: a pair works while its token lives.
	s3Works := func(t *testing.T, pair string) bool {
		t.Helper()
		accessKey, secretKey, _ := strings.Cut(pair, ":")
		vendor.mu.Lock()
		defer vendor.mu.Unlock()
		token, live := vendor.tokens[accessKey]
		return live && token[0] == "/accounts/"+servedCloudflareAccount+"/tokens" && crypto.SHA256Hex([]byte(token[2])) == secretKey
	}
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "cloudflare-r2", Type: "cloudflare-r2", Endpoint: stand.URL + "/client/v4",
			APIKeyRef:    writeServedCredentialFile(t, "cloudflare-r2-admin", "served-cloudflare-admin-token"),
			AllowedRoles: []string{"r2/backups"}, RoleBindings: map[string]string{"r2/backups": "account " + servedCloudflareAccount + " template " + servedCloudflareTemplate},
			MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "r2/backups", seed: `{"access_key_id":"issued-outside-trstctl","secret_access_key":"x"}`,
		keyOf: func(t *testing.T, credential string) string {
			t.Helper()
			var pair struct {
				AccessKeyID     string `json:"access_key_id"`
				SecretAccessKey string `json:"secret_access_key"`
				Endpoint        string `json:"endpoint"`
			}
			if err := json.Unmarshal([]byte(credential), &pair); err != nil || pair.AccessKeyID == "" || pair.SecretAccessKey == "" ||
				pair.Endpoint != "https://"+servedCloudflareAccount+".r2.cloudflarestorage.com" {
				t.Fatalf("the credential is not an R2 pair: %v", err)
			}
			return pair.AccessKeyID + ":" + pair.SecretAccessKey
		},
		authenticates: s3Works,
		newRefPrefix:  "account:" + servedCloudflareAccount + ":" + servedCloudflareTemplate + "/", leases: true, wantVerifyMode: "not_available",
	}.run(t)
	vendor.assertCopiedTemplate(t)
}
