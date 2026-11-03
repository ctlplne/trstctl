// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// servedOpenRouter is a stand-in for OpenRouter's key management API, built
// from its documentation: POST /keys with a management key returns the new
// key once at the top level and its hash under data; GET /keys pages by
// offset (100 a page); GET and DELETE /keys/{hash} answer 404 for an unknown
// hash; GET /key answers only for a live key.
type servedOpenRouter struct {
	mu     sync.Mutex
	keys   map[string][2]string // hash -> name, key
	limits map[string]any
	serial int
}

func (o *servedOpenRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if r.URL.Path == "/api/v1/key" {
		for hash, key := range o.keys {
			if "Bearer "+key[1] == r.Header.Get("Authorization") {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"label": hash[:8], "usage": 0, "limit": o.limits[hash]}})
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Authorization") != "Bearer served-openrouter-management-key" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	hash := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/api/v1/keys"), "/")
	switch {
	case r.Method == http.MethodPost && hash == "":
		var body struct {
			Name  string `json:"name"`
			Limit any    `json:"limit"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		o.serial++
		hash, key := fmt.Sprintf("served%058d", o.serial), fmt.Sprintf("sk-or-v1-served-%04d", o.serial)
		o.keys[hash], o.limits[hash] = [2]string{body.Name, key}, body.Limit
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"hash": hash, "name": body.Name, "label": key[:12] + "...", "limit": body.Limit}, "key": key})
	case r.Method == http.MethodGet && hash == "":
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		var hashes []string
		for candidate := range o.keys {
			hashes = append(hashes, candidate)
		}
		sort.Strings(hashes)
		data := []map[string]any{}
		for i := offset; i < len(hashes) && i < offset+100; i++ {
			data = append(data, map[string]any{"hash": hashes[i], "name": o.keys[hashes[i]][0], "label": "sk-or-v1-..."})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	case r.Method == http.MethodGet:
		key, ok := o.keys[hash]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"hash": hash, "name": key[0], "limit": o.limits[hash]}})
	case r.Method == http.MethodDelete:
		if _, ok := o.keys[hash]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(o.keys, hash)
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// A240 OpenRouter, against a stand-in of the key management API: a lease is
// an API key held to the role's credit limit that authenticates until
// revocation deletes it; a static rotation is two-phase, both keys working
// until the approved deadline, after which only the predecessor is deleted.
func TestServedOpenRouterKeysLeaseAndRotateA240(t *testing.T) {
	vendor := &servedOpenRouter{keys: map[string][2]string{}, limits: map[string]any{}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "openrouter-account", Type: "openrouter", Endpoint: stand.URL + "/api/v1",
			APIKeyRef:    writeServedCredentialFile(t, "openrouter-management", "served-openrouter-management-key"),
			AllowedRoles: []string{"openrouter/inference"}, RoleBindings: map[string]string{"openrouter/inference": "limit 25"},
			MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "openrouter/inference", seed: `{"api_key":"issued-outside-trstctl"}`,
		keyOf: func(t *testing.T, credential string) string {
			t.Helper()
			var parsed struct {
				APIKey  string `json:"api_key"`
				KeyHash string `json:"key_hash"`
			}
			if err := json.Unmarshal([]byte(credential), &parsed); err != nil || parsed.APIKey == "" || parsed.KeyHash == "" {
				t.Fatalf("the credential carries no API key: %v", err)
			}
			return parsed.APIKey
		},
		authenticates: func(t *testing.T, key string) bool {
			t.Helper()
			req, _ := http.NewRequest(http.MethodGet, stand.URL+"/api/v1/key", nil)
			req.Header.Set("Authorization", "Bearer "+key)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		},
		newRefPrefix: "limit-25/served", leases: true, wantVerifyMode: "authenticated",
	}.run(t)
	vendor.mu.Lock()
	defer vendor.mu.Unlock()
	for hash, limit := range vendor.limits {
		if _, live := vendor.keys[hash]; live && fmt.Sprint(limit) != "25" {
			t.Fatalf("key %s was created with limit %v, want the role's 25", hash, limit)
		}
	}
}
