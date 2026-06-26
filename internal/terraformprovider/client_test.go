package terraformprovider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientUsesServedOpenAPIRoutesAndHeaders(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-test" {
			t.Errorf("Authorization header = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Tenant-ID") != "tenant-a" {
			t.Errorf("X-Tenant-ID header = %q", r.Header.Get("X-Tenant-ID"))
		}
		if r.Method != http.MethodGet && r.Header.Get("Idempotency-Key") == "" {
			t.Errorf("%s %s missing Idempotency-Key", r.Method, r.URL.Path)
		}
		key := r.Method + " " + r.URL.Path
		seen[key] = true
		w.Header().Set("Content-Type", "application/json")
		switch key {
		case "POST /api/v1/profiles":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode profile request: %v", err)
			}
			if req["name"] != "web" {
				t.Fatalf("profile name = %v", req["name"])
			}
			_, _ = w.Write([]byte(`{"id":"prof-1","name":"web","version":1,"active":true,"created_by":"terraform","spec":{"ttl":"1h"}}`))
		case "GET /api/v1/profiles/web/versions/1":
			_, _ = w.Write([]byte(`{"id":"prof-1","name":"web","version":1,"active":true,"created_by":"terraform","spec":{"ttl":"1h"}}`))
		case "POST /api/v1/secrets/pki":
			_, _ = w.Write([]byte(`{"serial":"01","common_name":"svc.example.test","certificate":"CERT","private_key":"KEY"}`))
		case "POST /api/v1/secrets/store":
			_, _ = w.Write([]byte(`{"name":"apps/api/password","version":1,"created_at":"2026-06-26T01:00:00Z","updated_at":"2026-06-26T01:00:00Z"}`))
		case "GET /api/v1/secrets/store/apps/api/password":
			_, _ = w.Write([]byte(`{"name":"apps/api/password","value":"fixture-value","version":2}`))
		case "PUT /api/v1/secrets/store/apps/api/password":
			_, _ = w.Write([]byte(`{"name":"apps/api/password","version":2,"created_at":"2026-06-26T01:00:00Z","updated_at":"2026-06-26T01:01:00Z"}`))
		case "DELETE /api/v1/secrets/store/apps/api/password":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s", key)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(ClientConfig{Endpoint: srv.URL, Token: "tok-test", Tenant: "tenant-a", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.CreateProfile(t.Context(), "web", json.RawMessage(`{"ttl":"1h"}`), "idem-profile"); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	if _, err := client.GetProfileVersion(t.Context(), "web", 1); err != nil {
		t.Fatalf("GetProfileVersion: %v", err)
	}
	if _, err := client.IssuePKISecret(t.Context(), "svc.example.test", 3600, "idem-pki"); err != nil {
		t.Fatalf("IssuePKISecret: %v", err)
	}
	if _, err := client.CreateSecret(t.Context(), "apps/api/password", "fixture-value", "idem-secret-create"); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if _, err := client.GetSecret(t.Context(), "apps/api/password"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if _, err := client.RotateSecret(t.Context(), "apps/api/password", "fixture-value-2", "idem-secret-rotate"); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if err := client.DeleteSecret(t.Context(), "apps/api/password", "idem-secret-delete"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	for _, want := range []string{
		"POST /api/v1/profiles",
		"GET /api/v1/profiles/web/versions/1",
		"POST /api/v1/secrets/pki",
		"POST /api/v1/secrets/store",
		"GET /api/v1/secrets/store/apps/api/password",
		"PUT /api/v1/secrets/store/apps/api/password",
		"DELETE /api/v1/secrets/store/apps/api/password",
	} {
		if !seen[want] {
			t.Errorf("missing request %s", want)
		}
	}
}
