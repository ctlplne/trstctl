// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type cr232Vendor struct {
	*fakeVendor
	id string
}

func (v *cr232Vendor) mint(_ context.Context, _ hostedAPI, binding, name string) (string, []byte, error) {
	if v.keys[binding] == nil {
		v.keys[binding] = map[string]string{}
	}
	v.keys[binding][v.id] = name
	return v.id, []byte(`{"api_key":"fixture-value"}`), nil
}

func TestCR232EveryHostedKeyKindRevokesItsIssuedTarget(t *testing.T) {
	const cfA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const cfB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tc := range []struct{ kind, original, replacement, id string }{
		{"openrouter", "limit 25", "unlimited", "key-1"},
		{"fireworks", "acme/ci-bot", "acme/other-bot", "key-1"},
		{"litellm", "all-models", "models alpha", strings.Repeat("a", 64)},
		{"supabase", "abcdefghijklmnopqrst", "bcdefghijklmnopqrstu", "key-1"},
		{"convex", "happy-animal-123", "other-animal-456", "key-1"},
		{"dbt", "123 admin", "124 admin", "12345"},
		{"cloudflare", "template " + cfA, "template " + cfB, cfA},
		{"cloudflare-r2", "account " + cfA + " template " + cfB, "account " + cfB + " template " + cfA, cfA},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			ctx := context.Background()
			open := func(binding, prefix string) *HostedKeyBackend {
				t.Helper()
				b, err := NewHostedKeyBackend(tc.kind, HostedKeyConfig{
					Endpoint: "https://fixture.example", AdminKey: []byte("management"),
					RoleBindings: map[string]string{"role": binding}, UsernamePrefix: prefix, HTTPClient: http.DefaultClient,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(b.Close)
				return b
			}
			vendor := &cr232Vendor{fakeVendor: &fakeVendor{keys: map[string]map[string]string{}}, id: tc.id}
			before := open(tc.original, "trstctl")
			before.vendor = vendor
			ref, _, err := before.CreateCredential(ctx, GenerateRequest{
				Role: "role", LeaseID: fmt.Sprintf("cr232-%s", tc.kind), PrincipalSuffix: testPrincipalSuffix(tc.kind),
			})
			if err != nil || !strings.HasPrefix(ref, "v3:") {
				t.Fatalf("issued ref %q: %v", ref, err)
			}
			after := open(tc.replacement, "later")
			after.vendor = vendor
			if err := after.Revoke(ctx, ref); err != nil {
				t.Fatalf("revoke after binding and prefix change: %v", err)
			}
			if len(vendor.keys[before.bindings["role"]]) != 0 || len(vendor.removed) != 1 {
				t.Fatalf("issued key stayed live: %v, removed %v", vendor.keys, vendor.removed)
			}
		})
	}
}

func TestCR232FireworksRevokesAfterRoleRebind(t *testing.T) {
	ctx := context.Background()
	open := func(binding string) *HostedKeyBackend {
		t.Helper()
		b, err := NewHostedKeyBackend("fireworks", HostedKeyConfig{
			Endpoint: "https://fireworks.example", AdminKey: []byte("management"),
			RoleBindings: map[string]string{"ci": binding}, HTTPClient: http.DefaultClient,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Close)
		return b
	}
	vendor := &fakeVendor{keys: map[string]map[string]string{}}
	before := open("acme/ci-bot")
	before.vendor = vendor
	ref, _, err := before.CreateCredential(ctx, GenerateRequest{Role: "ci", LeaseID: "cr232-fireworks", PrincipalSuffix: testPrincipalSuffix("cr232-fireworks")})
	if err != nil {
		t.Fatal(err)
	}
	after := open("acme/other-bot")
	after.vendor = vendor
	if err := after.Revoke(ctx, ref); err != nil {
		t.Fatalf("revoke after Fireworks rebind: %v", err)
	}
	if len(vendor.removed) != 1 || len(vendor.keys["acme:ci-bot"]) != 0 {
		t.Fatalf("old Fireworks key remained live: %v", vendor.keys)
	}
}

func TestCR232ClientSecretRevokesAfterRoleRebind(t *testing.T) {
	ctx := context.Background()
	open := func(binding string) *ClientSecretBackend {
		t.Helper()
		b, err := NewClientSecretBackend("okta", ClientSecretConfig{
			Endpoint: "https://acme.okta.example", AdminKey: []byte("ssws"),
			RoleBindings: map[string]string{"portal": binding}, HTTPClient: http.DefaultClient,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Close)
		return b
	}
	vendor := &fakeClientSecrets{secrets: map[string]map[string]bool{}}
	before := open("0oa1b2c3d4e5f6g7h8i9")
	before.vendor = vendor
	ref, _, err := before.CreateCredential(ctx, GenerateRequest{Role: "portal", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	after := open("0oaother000000000000")
	after.vendor = vendor
	if err := after.Revoke(ctx, ref); err != nil {
		t.Fatalf("revoke after client rebind: %v", err)
	}
	if vendor.secrets["0oa1b2c3d4e5f6g7h8i9"]["sx"] {
		t.Fatal("old Okta client secret remained live")
	}
}

func TestCR232DatabricksClientSecretRevokesAfterRoleRebind(t *testing.T) {
	ctx := context.Background()
	const account = "a1b2c3d4-0000-4000-8000-0123456789ab"
	open := func(binding, adminID string) *ClientSecretBackend {
		t.Helper()
		b, err := NewClientSecretBackend("databricks", ClientSecretConfig{
			Endpoint: "https://accounts.cloud.databricks.com", AdminKey: []byte("admin-secret"), AdminClientID: adminID,
			RoleBindings: map[string]string{"etl": binding}, HTTPClient: http.DefaultClient,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Close)
		return b
	}
	vendor := &fakeClientSecrets{secrets: map[string]map[string]bool{}}
	before := open(account+" 4471", "admin-a")
	before.vendor = vendor
	ref, _, err := before.CreateCredential(ctx, GenerateRequest{Role: "etl", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	wrongAdmin := open(account+" 4472", "admin-b")
	wrongAdmin.vendor = vendor
	if err := wrongAdmin.Revoke(ctx, ref); err == nil || len(vendor.removed) != 0 {
		t.Fatal("another administrator identity accepted the issued reference")
	}
	after := open(account+" 4472", "admin-a")
	after.vendor = vendor
	if err := after.Revoke(ctx, ref); err != nil {
		t.Fatalf("revoke after service principal rebind: %v", err)
	}
	if vendor.secrets[account+":4471"]["sx"] || len(vendor.removed) != 1 {
		t.Fatalf("old Databricks client secret remained live: %v", vendor.secrets)
	}
}

func TestCR232OpenAIRevokesAfterProjectRebind(t *testing.T) {
	ctx := context.Background()
	fake := &fakeOpenAI{accounts: map[string]fakeOpenAIAccount{}}
	server := httptest.NewServer(fake)
	defer server.Close()
	open := func(project string) *OpenAIBackend {
		t.Helper()
		b, err := NewOpenAIBackend(OpenAIConfig{
			Endpoint: server.URL, AdminKey: []byte("sk-admin-fixture"),
			RoleBindings: map[string]string{"orders": project}, UsernamePrefix: "trstctl",
			AllowInsecureLoopback: true, HTTPClient: server.Client(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Close)
		return b
	}
	ref, _, err := open("proj_orders").CreateCredential(ctx, GenerateRequest{Role: "orders", LeaseID: "cr232-openai", PrincipalSuffix: testPrincipalSuffix("cr232-openai")})
	if err != nil {
		t.Fatal(err)
	}
	if err := open("proj_billing").Revoke(ctx, ref); err != nil {
		t.Fatalf("revoke after project rebind: %v", err)
	}
	if fake.named("trstctl-") != 0 {
		t.Fatal("old OpenAI service-account key remained live")
	}
}

func TestCR232APIConnectRevokesAfterAppRebind(t *testing.T) {
	ctx := context.Background()
	lab, server := newAPIConnectStandIn(t)
	open := func(app string) *APIConnectBackend {
		t.Helper()
		b, err := NewAPIConnectBackend(APIConnectConfig{
			Endpoint: server.URL, ClientID: "toolkit", ClientSecret: []byte("toolkit-secret"),
			APIKey: []byte("lab-api-key"), RoleBindings: map[string]string{"partner": app},
			UsernamePrefix: "trstctl", AllowInsecureLoopback: true, HTTPClient: server.Client(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Close)
		return b
	}
	ref, _, err := open(apiConnectLabApp).CreateCredential(ctx, GenerateRequest{Role: "partner", LeaseID: "cr232-apic", PrincipalSuffix: testPrincipalSuffix("cr232-apic")})
	if err != nil {
		t.Fatal(err)
	}
	if err := open("acme/sandbox/partners/other-app").Revoke(ctx, ref); err != nil {
		t.Fatalf("revoke after app rebind: %v", err)
	}
	if len(lab.credentials) != 0 {
		t.Fatal("old API Connect app credential remained live")
	}
}

// CR-232: the role is a creation policy. Revoke must follow the original
// target and key in the stored reference after an operator changes that role.
func TestCR232HostedKeyRevokesAfterRoleRebind(t *testing.T) {
	ctx := context.Background()
	before, vendor := fakeHostedBackend(t)
	ref, _, err := before.CreateCredential(ctx, GenerateRequest{
		Role: "inference", LeaseID: "cr232-hosted", PrincipalSuffix: testPrincipalSuffix("cr232-hosted"),
	})
	if err != nil {
		t.Fatal(err)
	}
	before.Close()
	after, _ := fakeHostedBackend(t)
	after.vendor = vendor
	after.bindings["inference"] = "unlimited"
	if err := after.Revoke(ctx, ref); err != nil {
		t.Fatalf("revoke after role rebind: %v", err)
	}
	if len(vendor.keys["limit-25"]) != 0 || len(vendor.removed) != 1 {
		t.Fatalf("old hosted key remained live: %v, removed %v", vendor.keys, vendor.removed)
	}
}

func TestCR232HostedReferenceCannotSwapTheIssuedBinding(t *testing.T) {
	ctx := context.Background()
	backend, vendor := fakeHostedBackend(t)
	ref, _, err := backend.CreateCredential(ctx, GenerateRequest{
		Role: "inference", LeaseID: "cr232-bind", PrincipalSuffix: testPrincipalSuffix("cr232-bind"),
	})
	if err != nil {
		t.Fatal(err)
	}
	name := vendor.keys["limit-25"]["key-1"]
	vendor.keys["unlimited"] = map[string]string{"key-1": name}
	tampered := strings.Replace(ref, "limit-25/key-1", "unlimited/key-1", 1)
	if tampered == ref {
		t.Fatal("test did not change the issued binding")
	}
	if err := backend.Revoke(ctx, tampered); err == nil {
		t.Fatal("swapped binding deleted a key that was not in this issued reference")
	}
	if vendor.keys["limit-25"]["key-1"] == "" || vendor.keys["unlimited"]["key-1"] == "" {
		t.Fatalf("swapped reference removed a key: %v", vendor.keys)
	}
}

func TestCR232DatadogRevokesAfterServiceAccountRebind(t *testing.T) {
	ctx := context.Background()
	fake := &fakeDatadog{keys: map[string]datadogFakeKey{}}
	server := httptest.NewServer(fake)
	defer server.Close()
	open := func(account string) *DatadogBackend {
		t.Helper()
		backend, err := NewDatadogBackend(DatadogConfig{
			Endpoint: server.URL, APIKey: []byte("admin-api-key"), ApplicationKey: []byte("admin-app-key"),
			RoleBindings:   map[string]string{"metrics": "application_key " + account + " metrics_read"},
			UsernamePrefix: "trstctl", AllowInsecureLoopback: true, HTTPClient: server.Client(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return backend
	}
	before := open("3f1e7e1a-1111-4222-8333-444455556666")
	ref, _, err := before.CreateCredential(ctx, GenerateRequest{
		Role: "metrics", LeaseID: "cr232-datadog", PrincipalSuffix: testPrincipalSuffix("cr232-datadog"),
	})
	if err != nil {
		t.Fatal(err)
	}
	before.Close()
	after := open("3f1e7e1a-1111-4222-8333-444455556667")
	defer after.Close()
	if err := after.Revoke(ctx, ref); err != nil {
		t.Fatalf("revoke after service-account rebind: %v", err)
	}
	if fake.count("trstctl-") != 0 {
		t.Fatal("Datadog predecessor key remained live after revoke")
	}
}
