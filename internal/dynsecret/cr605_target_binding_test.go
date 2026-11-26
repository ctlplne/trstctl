// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestCR605OpenAIRevokeRefusesAnotherOrganizationAtSameEndpoint(t *testing.T) {
	orgA := &fakeOpenAI{accounts: map[string]fakeOpenAIAccount{}}
	orgB := &fakeOpenAI{accounts: map[string]fakeOpenAIAccount{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forward := r.Clone(r.Context())
		switch r.Header.Get("Authorization") {
		case "Bearer org-a-admin":
			forward.Header.Set("Authorization", "Bearer sk-admin-fixture")
			orgA.ServeHTTP(w, forward)
		case "Bearer org-b-admin":
			forward.Header.Set("Authorization", "Bearer sk-admin-fixture")
			orgB.ServeHTTP(w, forward)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	open := func(admin string) *OpenAIBackend {
		t.Helper()
		b, err := NewOpenAIBackend(OpenAIConfig{Endpoint: srv.URL, AdminKey: []byte(admin),
			RoleBindings: map[string]string{"orders": "proj_orders"}, AllowInsecureLoopback: true, HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Close)
		return b
	}
	ref, _, err := open("org-a-admin").CreateCredential(t.Context(), GenerateRequest{
		Role: "orders", LeaseID: "lease-cr605-openai", PrincipalSuffix: testPrincipalSuffix("lease-cr605-openai"),
	})
	if err != nil || orgA.named("trstctl-") != 1 {
		t.Fatalf("issue in org A: %v, accounts=%d", err, orgA.named("trstctl-"))
	}
	if err := open("org-b-admin").Revoke(t.Context(), ref); err == nil {
		t.Fatal("another organization's admin key reported revoked while org A still holds a live service account")
	}
	if orgA.named("trstctl-") != 1 {
		t.Fatal("wrong-organization revoke changed the original service account")
	}
}

func TestCR605OpenRouterRevokeRefusesAnotherAccountAtSameEndpoint(t *testing.T) {
	open := func(admin string, vendor *fakeVendor) *HostedKeyBackend {
		t.Helper()
		b, err := NewHostedKeyBackend("openrouter", HostedKeyConfig{
			Endpoint: "https://openrouter.ai/api/v1", AdminKey: []byte(admin),
			RoleBindings: map[string]string{"inference": "limit 25"}, HTTPClient: http.DefaultClient,
		})
		if err != nil {
			t.Fatal(err)
		}
		b.vendor = vendor
		t.Cleanup(b.Close)
		return b
	}
	accountA := &fakeVendor{keys: map[string]map[string]string{}}
	accountB := &fakeVendor{keys: map[string]map[string]string{}}
	ref, _, err := open("account-a-management", accountA).CreateCredential(t.Context(), GenerateRequest{
		Role: "inference", LeaseID: "lease-cr605-openrouter", PrincipalSuffix: testPrincipalSuffix("lease-cr605-openrouter"),
	})
	if err != nil || len(accountA.keys["limit-25"]) != 1 {
		t.Fatalf("issue in account A: %v, keys=%v", err, accountA.keys)
	}
	if err := open("account-b-management", accountB).Revoke(t.Context(), ref); err == nil {
		t.Fatal("another account's management key reported revoked while account A's key is live")
	}
	if len(accountA.keys["limit-25"]) != 1 {
		t.Fatal("wrong-account revoke changed the original key")
	}
	raw, _, err := opaqueFromBoundRef(ref, "openrouter", "https://openrouter.ai/api/v1", open("account-a-management", accountA).adminIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := open("account-a-management", accountA).Revoke(t.Context(), raw); err == nil || len(accountA.keys["limit-25"]) != 1 {
		t.Fatal("a historical target-unbound reference was treated as proof of revocation")
	}
	reconfigured, err := NewHostedKeyBackend("openrouter", HostedKeyConfig{
		Endpoint: "https://openrouter.ai/api/v1", AdminKey: []byte("account-a-management"), UsernamePrefix: "later",
		RoleBindings: map[string]string{"inference": "limit 25"}, HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	reconfigured.vendor = accountA
	t.Cleanup(reconfigured.Close)
	if err := reconfigured.Revoke(t.Context(), ref); err != nil || len(accountA.keys["limit-25"]) != 0 {
		t.Fatalf("original account could not revoke after prefix edit: %v", err)
	}
}

func TestCR605TailscaleRevokeRefusesAnotherTailnetAtSameEndpoint(t *testing.T) {
	var mu sync.Mutex
	keys := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.Header.Get("Authorization") == "Bearer tailnet-a-token":
			keys["kCR605"] = true
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "kCR605", "key": "tskey-auth-fixture", "expires": "2026-12-01T00:00:00Z"})
		case r.Method == http.MethodDelete && r.Header.Get("Authorization") == "Bearer tailnet-a-token":
			delete(keys, "kCR605")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.Header.Get("Authorization") == "Bearer tailnet-b-token":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	open := func(token string) *TailscaleBackend {
		t.Helper()
		b, err := NewTailscaleBackend(TailscaleConfig{Endpoint: srv.URL, APIToken: []byte(token),
			RoleBindings: map[string]string{"ci": "tag:ci"}, MaxLifetime: time.Hour,
			AllowInsecureLoopback: true, HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Close)
		return b
	}
	ref, _, err := open("tailnet-a-token").CreateCredential(t.Context(), GenerateRequest{Role: "ci", LeaseID: "lease-cr605-tailscale"})
	if err != nil || !keys["kCR605"] {
		t.Fatalf("issue in tailnet A: %v, keys=%v", err, keys)
	}
	if err := open("tailnet-b-token").Revoke(t.Context(), ref); err == nil {
		t.Fatal("another tailnet's API token reported revoked while the original auth key is live")
	}
	if !keys["kCR605"] {
		t.Fatal("wrong-tailnet revoke changed the original key")
	}
}
