// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCR232OpenRouterLeaseRequestsNativeExpiry(t *testing.T) {
	var expires string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/keys":
			var request struct {
				ExpiresAt string `json:"expires_at"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			expires = request.ExpiresAt
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"hash":"hash-232"},"key":"sk-fixture"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	b, err := NewHostedKeyBackend("openrouter", HostedKeyConfig{
		Endpoint: server.URL, AdminKey: []byte("management"), RoleBindings: map[string]string{"role": "unlimited"},
		AllowInsecureLoopback: true, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	start := time.Now()
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{
		Role: "role", LeaseID: "cr232-openrouter-expiry", PrincipalSuffix: testPrincipalSuffix("cr232-openrouter-expiry"), TTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || got.Before(start.Add(time.Hour)) || got.After(time.Now().Add(time.Hour+5*time.Second)) {
		t.Fatalf("OpenRouter expires_at = %q (%v), want one-hour lease bound", expires, err)
	}
}

func TestCR232CloudflareLeasesRequestNativeExpiry(t *testing.T) {
	const account = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const template = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tc := range []struct{ kind, binding, path string }{
		{"cloudflare", "template " + template, "/user/tokens"},
		{"cloudflare-r2", "account " + account + " template " + template, "/accounts/" + account + "/tokens"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			var expires string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == tc.path:
					_, _ = w.Write([]byte(`{"success":true,"result":[],"result_info":{"total_pages":1}}`))
				case r.Method == http.MethodGet && r.URL.Path == tc.path+"/"+template:
					_, _ = w.Write([]byte(`{"success":true,"result":{"policies":[{"effect":"allow","permission_groups":[{"id":"fixture"}],"resources":{"*":"*"}}]}}`))
				case r.Method == http.MethodPost && r.URL.Path == tc.path:
					var request struct {
						ExpiresOn string `json:"expires_on"`
					}
					_ = json.NewDecoder(r.Body).Decode(&request)
					expires = request.ExpiresOn
					_, _ = w.Write([]byte(`{"success":true,"result":{"id":"` + account + `","value":"fixture-token","name":"trstctl-role-0123456789abcdef"}}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			b, err := NewHostedKeyBackend(tc.kind, HostedKeyConfig{
				Endpoint: server.URL, AdminKey: []byte("management"), RoleBindings: map[string]string{"role": tc.binding},
				AllowInsecureLoopback: true, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			start := time.Now()
			if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{
				Role: "role", LeaseID: "cr232-cloudflare-expiry", PrincipalSuffix: testPrincipalSuffix(tc.kind), TTL: time.Hour,
			}); err != nil {
				t.Fatal(err)
			}
			got, err := time.Parse(time.RFC3339Nano, expires)
			if err != nil || got.Before(start.Add(time.Hour)) || got.After(time.Now().Add(time.Hour+5*time.Second)) || strings.TrimSpace(expires) != expires {
				t.Fatalf("%s expires_on = %q (%v), want one-hour lease bound", tc.kind, expires, err)
			}
		})
	}
}
