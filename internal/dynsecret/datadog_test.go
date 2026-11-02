// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeDatadog is a stand-in for the Datadog key API from its documentation:
// API keys and service-account application keys are created (the key shown
// once), listed by name filter, read and deleted; /api/v1/validate accepts a
// live API key.
type fakeDatadog struct {
	mu     sync.Mutex
	keys   map[string]datadogFakeKey // id -> key
	serial int
}

type datadogFakeKey struct {
	collection, name, key string
	scopes                []string
}

func (f *fakeDatadog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/api/v1/validate" {
		for _, key := range f.keys {
			if key.collection == "/api/v2/api_keys" && key.key == r.Header.Get("DD-API-KEY") {
				_, _ = w.Write([]byte(`{"valid":true}`))
				return
			}
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Header.Get("DD-API-KEY") != "admin-api-key" || r.Header.Get("DD-APPLICATION-KEY") != "admin-app-key" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	collection, id := r.URL.Path, ""
	if strings.HasPrefix(r.URL.Path, "/api/v2/api_keys/") || strings.Count(r.URL.Path, "/") == 6 {
		cut := strings.LastIndex(r.URL.Path, "/")
		collection, id = r.URL.Path[:cut], r.URL.Path[cut+1:]
	}
	switch {
	case r.Method == http.MethodPost && id == "":
		var body struct {
			Data struct {
				Attributes struct {
					Name   string   `json:"name"`
					Scopes []string `json:"scopes"`
				} `json:"attributes"`
			} `json:"data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.serial++
		id := fmt.Sprintf("key-%04d", f.serial)
		key := fmt.Sprintf("%032x", f.serial)
		f.keys[id] = datadogFakeKey{collection: collection, name: body.Data.Attributes.Name, key: key, scopes: body.Data.Attributes.Scopes}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": id, "attributes": map[string]any{"key": key, "name": body.Data.Attributes.Name}}})
	case r.Method == http.MethodGet && id == "":
		filter := r.URL.Query().Get("filter")
		var data []map[string]any
		for keyID, key := range f.keys {
			if key.collection == collection && strings.Contains(key.name, filter) {
				data = append(data, map[string]any{"id": keyID, "attributes": map[string]any{"name": key.name}})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	case r.Method == http.MethodGet:
		key, ok := f.keys[id]
		if !ok || key.collection != collection {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": id, "attributes": map[string]any{"name": key.name}}})
	case r.Method == http.MethodDelete:
		if _, ok := f.keys[id]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.keys, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeDatadog) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, key := range f.keys {
		if strings.Contains(key.name, name) {
			n++
		}
	}
	return n
}

// A240: Datadog keys rotate in two phases. Each rotation (or lease) creates a
// new named key, both keys work until the predecessor is retired, retirement
// deletes only keys this provider named, and a retried creation replaces its
// key instead of adding one.
func TestDatadogKeysRotateInTwoPhases(t *testing.T) {
	ctx := context.Background()
	fake := &fakeDatadog{keys: map[string]datadogFakeKey{"key-foreign": {collection: "/api/v2/api_keys", name: "production-ingest", key: "f00d"}}}
	server := httptest.NewServer(fake)
	defer server.Close()
	backend, err := NewDatadogBackend(DatadogConfig{Endpoint: server.URL, APIKey: []byte("admin-api-key"), ApplicationKey: []byte("admin-app-key"),
		RoleBindings: map[string]string{
			"datadog/ingest":  "api_key",
			"datadog/metrics": "application_key 3f1e7e1a-1111-4222-8333-444455556666 metrics_read,timeseries_query",
		}, UsernamePrefix: "trstctl", AllowInsecureLoopback: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	if _, _, err := backend.CreateCredential(ctx, GenerateRequest{Role: "datadog/ingest", LeaseID: "cmd-1", Static: true}); err != nil {
		t.Fatal(err)
	}
	// A retry of the same command replaces its key instead of adding one.
	oldRef, oldKey, err := backend.CreateCredential(ctx, GenerateRequest{Role: "datadog/ingest", LeaseID: "cmd-1", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	if fake.count("trstctl-") != 1 {
		t.Fatalf("a retried creation left %d keys", fake.count("trstctl-"))
	}
	newRef, newKey, err := backend.CreateCredential(ctx, GenerateRequest{Role: "datadog/ingest", LeaseID: "cmd-2", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.VerifyCredential(ctx, oldKey); err != nil {
		t.Fatalf("the predecessor stopped before retirement: %v", err)
	}
	if err := backend.VerifyCredential(ctx, newKey); err != nil {
		t.Fatalf("the successor does not validate: %v", err)
	}
	if err := backend.Revoke(ctx, oldRef); err != nil {
		t.Fatal(err)
	}
	if err := backend.VerifyCredential(ctx, oldKey); err == nil {
		t.Fatal("the retired key still validates")
	}
	if err := backend.VerifyCredential(ctx, newKey); err != nil {
		t.Fatalf("retiring the predecessor broke the successor: %v", err)
	}
	if err := backend.Revoke(ctx, oldRef); err != nil {
		t.Fatalf("a key already gone counts as revoked: %v", err)
	}
	if err := backend.Revoke(ctx, "api_key/key-foreign"); err == nil || !strings.Contains(err.Error(), "did not create") {
		t.Fatalf("a key this provider did not name was deleted: %v", err)
	}
	if err := backend.Revoke(ctx, "00000000-0000-4000-8000-000000000000/key-0001"); err == nil {
		t.Fatal("a key of an unbound service account was accepted")
	}
	_ = newRef

	appRef, appKey, err := backend.CreateCredential(ctx, GenerateRequest{Role: "datadog/metrics", LeaseID: "lease-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(appRef, "3f1e7e1a-1111-4222-8333-444455556666/") || !strings.Contains(string(appKey), `"application_key"`) {
		t.Fatalf("application key = %q %s", appRef, appKey)
	}
	fake.mu.Lock()
	_, id, _ := strings.Cut(appRef, "/")
	scopes := fake.keys[id].scopes
	fake.mu.Unlock()
	if strings.Join(scopes, ",") != "metrics_read,timeseries_query" {
		t.Fatalf("application key scopes = %v", scopes)
	}
	if err := backend.VerifyCredential(ctx, appKey); !errors.Is(err, ErrNoSelfProof) {
		t.Fatalf("an application key claimed a proof: %v", err)
	}
	if err := backend.Revoke(ctx, appRef); err != nil || fake.count("trstctl-") != 1 {
		t.Fatalf("revoke the application key: %v (%d keys left)", err, fake.count("trstctl-"))
	}
	for _, binding := range []string{"", "api_keys", "application_key not-an-id metrics_read", "application_key 3f1e7e1a-1111-4222-8333-444455556666 Metrics Read"} {
		if _, err := ParseDatadogBinding(binding); err == nil {
			t.Errorf("binding %q accepted", binding)
		}
	}
}
