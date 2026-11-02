// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type elasticsearchLab struct {
	mu        sync.Mutex
	keys      map[string]map[string]any // id -> {name, invalidated, request}
	next      int
	createErr bool
}

func newElasticsearchLab(t *testing.T) (*elasticsearchLab, *httptest.Server) {
	t.Helper()
	lab := &elasticsearchLab{keys: map[string]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); !ok || user != "elastic" || pass != "lab-elastic-password" { // #nosec G101 -- fabricated lab administrator password (CWE-798)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		lab.mu.Lock()
		defer lab.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/_security/api_key":
			var found []map[string]string
			for id, key := range lab.keys {
				if key["name"] == r.URL.Query().Get("name") && key["invalidated"] != true {
					found = append(found, map[string]string{"id": id})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"api_keys": found})
		case r.Method == http.MethodPost && r.URL.Path == "/_security/api_key":
			if lab.createErr {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"type":"security_exception","reason":"secret details"}}`))
				return
			}
			var request map[string]any
			_ = json.NewDecoder(r.Body).Decode(&request)
			lab.next++
			id := fmt.Sprintf("key%d", lab.next)
			lab.keys[id] = map[string]any{"name": request["name"], "request": request}
			apiKey := fmt.Sprintf("secret%d", lab.next)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "name": request["name"], "api_key": apiKey,
				"encoded": base64.StdEncoding.EncodeToString([]byte(id + ":" + apiKey)), "expiration": int64(1793634575907)})
		case r.Method == http.MethodDelete && r.URL.Path == "/_security/api_key":
			var request struct {
				IDs []string `json:"ids"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			var invalidated []string
			for _, id := range request.IDs {
				if key, ok := lab.keys[id]; ok && key["invalidated"] != true {
					key["invalidated"] = true
					invalidated = append(invalidated, id)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"invalidated_api_keys": invalidated, "previously_invalidated_api_keys": []string{}, "error_count": 0})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return lab, srv
}

func newLabElasticsearch(t *testing.T, srv *httptest.Server) *ElasticsearchBackend {
	t.Helper()
	b, err := NewElasticsearchBackend(ElasticsearchConfig{
		Endpoint: srv.URL, AdminUser: "elastic", AdminPassword: []byte("lab-elastic-password"),
		RoleBindings: map[string]string{"reader": "read,view_index_metadata on logs-*,metrics-*"}, MaxLifetime: time.Hour,
		AllowInsecureLoopback: true, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestElasticsearchLeaseIsAnAPIKeyWithTheRoleIndexGrantA239(t *testing.T) {
	lab, srv := newElasticsearchLab(t)
	b := newLabElasticsearch(t, srv)
	req := GenerateRequest{Role: "reader", TTL: 10 * time.Minute, LeaseID: "lease-0001"}
	ref, credential, err := b.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		ID        string    `json:"id"`
		APIKey    string    `json:"api_key"`
		Encoded   string    `json:"encoded"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(credential, &got); err != nil || ref != "es-apikey:"+got.ID || got.APIKey == "" || got.Encoded == "" || got.ExpiresAt.IsZero() {
		t.Fatalf("ref %q credential %+v (%v)", ref, got, err)
	}
	request := lab.keys[got.ID]["request"].(map[string]any)
	if request["expiration"] != "3600s" {
		t.Fatalf("expiration %v, want the maximum lifetime", request["expiration"])
	}
	descriptor, _ := json.Marshal(request["role_descriptors"])
	if string(descriptor) != `{"trstctl_lease":{"cluster":[],"indices":[{"names":["logs-*","metrics-*"],"privileges":["read","view_index_metadata"]}]}}` {
		t.Fatalf("role descriptors %s", descriptor)
	}
	// A retry of the same lease invalidates the key the first attempt left.
	ref2, _, err := b.CreateCredential(context.Background(), req)
	if err != nil || ref2 == ref || lab.keys[got.ID]["invalidated"] != true {
		t.Fatalf("retry: ref %q (%v); first key invalidated=%v", ref2, err, lab.keys[got.ID]["invalidated"])
	}
	if err := b.Revoke(context.Background(), ref2); err != nil {
		t.Fatal(err)
	}
	id2 := strings.TrimPrefix(ref2, "es-apikey:")
	if lab.keys[id2]["invalidated"] != true {
		t.Fatal("revocation did not invalidate the key")
	}
	if err := b.Revoke(context.Background(), ref2); err != nil {
		t.Fatalf("a second revocation of an invalidated key: %v", err)
	}
	for _, foreign := range []string{"key1", "es-apikey:", "es-apikey:../x", "trstctl_reader_1"} {
		if err := b.Revoke(context.Background(), foreign); err == nil {
			t.Errorf("revoked %q, not a reference this provider issued", foreign)
		}
	}
}

func TestElasticsearchFailureNamesOnlyTheErrorTypeA239(t *testing.T) {
	lab, srv := newElasticsearchLab(t)
	lab.createErr = true
	b := newLabElasticsearch(t, srv)
	_, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-0002"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 403 (security_exception)") || strings.Contains(err.Error(), "secret details") {
		t.Fatalf("error %v", err)
	}
}

func TestElasticsearchIndexGrantGrammarA239(t *testing.T) {
	grant, err := ParseElasticsearchIndexGrant("read, view_index_metadata on logs-*, .ds-logs-*")
	if err != nil || strings.Join(grant.Privileges, "|") != "read|view_index_metadata" || strings.Join(grant.Names, "|") != "logs-*|.ds-logs-*" {
		t.Fatalf("grant %+v (%v)", grant, err)
	}
	for _, bad := range []string{"read", "read on ", "Read on logs", `read on logs"`, "read on logs,a b", "all; DROP on x"} {
		if _, err := ParseElasticsearchIndexGrant(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := NewElasticsearchBackend(ElasticsearchConfig{Endpoint: "http://es.example:9200", AdminUser: "elastic",
		AdminPassword: []byte("x"), MaxLifetime: time.Hour, HTTPClient: http.DefaultClient}); err == nil {
		t.Error("accepted a plain-HTTP endpoint off loopback")
	}
}
