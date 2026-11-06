// SPDX-License-Identifier: BUSL-1.1
package azureiam

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

func goodConfig() Config {
	return Config{TenantID: "10000000-0000-0000-0000-000000000001", SubscriptionID: "20000000-0000-0000-0000-000000000002", PrincipalIDs: []string{"30000000-0000-0000-0000-000000000003"}, GraphTokenFileRef: strings.Join([]string{"env", "OWNED_GRAPH_READER"}, ":"), ARMTokenFileRef: strings.Join([]string{"env", "OWNED_ARM_READER"}, ":")}
}
func TestAzureSourceBoundsAndAuthorityA264(t *testing.T) {
	good := goodConfig()
	raw, _ := json.Marshal(good)
	if _, err := DecodeConfig(raw); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Config){"inline": func(c *Config) { c.GraphTokenFileRef = "inline" }, "same audience": func(c *Config) { c.ARMTokenFileRef = c.GraphTokenFileRef }, "path injection": func(c *Config) { c.PrincipalIDs = []string{"../foreign"} }, "duplicate principal": func(c *Config) { c.PrincipalIDs = append(c.PrincipalIDs, c.PrincipalIDs[0]) }, "implicit beta": func(c *Config) { c.ActivityLookbackDays = 30 }, "beta without window": func(c *Config) { c.ReadBetaSignins = true }, "overlong activity": func(c *Config) { c.ReadBetaSignins = true; c.ActivityLookbackDays = 31 }, "origin path": func(c *Config) { c.GraphEndpoint = "https://graph.microsoft.com/another" }, "plaintext": func(c *Config) { c.ARMEndpoint = "http://127.0.0.1:1" }, "foreign managed principal": func(c *Config) { c.ManagedIdentityResources = map[string]string{"foreign": "/subscriptions/owned"} }} {
		t.Run(name, func(t *testing.T) {
			c := good
			change(&c)
			raw, _ := json.Marshal(c)
			if _, err := DecodeConfig(raw); err == nil {
				t.Fatal("invalid source admitted")
			}
		})
	}
	for _, raw := range []string{`{"azure_tenant_id":"one","Azure_Tenant_Id":"two"}`, `{"graph_token_file_ref":"env:ONE","graph_token_file_ref":"env:TWO"}`, `{"client_secret":"inline"}`} {
		if _, err := DecodeConfig([]byte(raw)); err == nil {
			t.Fatal("ambiguous source admitted")
		}
	}
}
func TestAzureNativePaginationCannotChangeAuthorityA264(t *testing.T) {
	origin := "https://graph.microsoft.com"
	initial := "/v1.0/servicePrincipals/owned/appRoleAssignments?%24select=id"
	for _, next := range []string{"https://foreign.test" + initial, "http://graph.microsoft.com" + initial, "https://user@graph.microsoft.com" + initial, "https://graph.microsoft.com/v1.0/another?%24select=id", "https://graph.microsoft.com" + initial + "&%24select=secretText", "https://graph.microsoft.com" + initial + "&extra=value", "https://graph.microsoft.com" + initial + "#fragment", "https://graph.microsoft.com/v1.0/servicePrincipals/%6fwned/appRoleAssignments?%24select=id"} {
		if _, err := nextPage(origin, initial, next); err == nil {
			t.Fatalf("foreign/altered cursor admitted: %s", next)
		}
	}
	if err := quick.Check(func(cursor string) bool {
		if len(cursor) > 8192 {
			return true
		}
		next := origin + initial + "&%24skiptoken=" + url.QueryEscape(cursor)
		path, err := nextPage(origin, initial, next)
		if err != nil {
			return false
		}
		u, err := url.Parse(path)
		return err == nil && u.Host == "" && u.Path == "/v1.0/servicePrincipals/owned/appRoleAssignments" && u.Query().Get("$select") == "id" && u.Query().Get("$skiptoken") == cursor
	}, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
func TestAzureCredentialNativeBindingsA264(t *testing.T) {
	now := time.Now()
	key := Credential{ID: "70000000-0000-0000-0000-000000000007", Start: now.Add(-time.Hour), End: now.Add(time.Hour)}
	if validateCredentials([]Credential{key}, nil, now) != nil {
		t.Fatal("valid metadata refused")
	}
	if validateCredentials([]Credential{key}, []Credential{key}, now) == nil {
		t.Fatal("duplicate credential across native kinds accepted")
	}
	key.End = key.Start.Add(-time.Hour)
	if validateCredentials([]Credential{key}, nil, now) == nil {
		t.Fatal("inverted dates accepted")
	}
}
func FuzzAzureMachineSourceA264(f *testing.F) {
	raw, _ := json.Marshal(goodConfig())
	f.Add(raw)
	f.Add([]byte(`{"azure_tenant_id":"one","Azure_Tenant_Id":"two"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) <= 64<<10 {
			_, _ = DecodeConfig(raw)
		}
	})
}
func FuzzAzureInventoryRecordA264(f *testing.F) {
	cfg := goodConfig()
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	value := Inventory{Version: 1, Provider: "azure-entra", TenantID: cfg.TenantID, SubscriptionID: cfg.SubscriptionID, SourceOrigin: "https://graph.microsoft.com", SourceFingerprint: strings.Repeat("a", 64), CollectedAt: now, Identity: Identity{ID: cfg.PrincipalIDs[0], AppID: cfg.TenantID, Type: "Application", Keys: []Credential{{ID: cfg.SubscriptionID, Start: now.Add(-time.Hour), End: now.Add(time.Hour)}}}}
	raw, _ := json.Marshal(value)
	f.Add(raw)
	f.Add([]byte(`{"version":1,"provider":"azure-entra"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) <= 512<<10 {
			_, _ = DecodeInventory(raw)
		}
	})
}
func FuzzAzurePaginationA264(f *testing.F) {
	f.Add("https://graph.microsoft.com/v1.0/items?%24select=id&%24skiptoken=next")
	f.Fuzz(func(t *testing.T, next string) {
		if len(next) > 16384 {
			return
		}
		path, err := nextPage("https://graph.microsoft.com", "/v1.0/items?%24select=id", next)
		if err == nil {
			u, e := url.Parse(path)
			if e != nil || u.Host != "" || u.Path != "/v1.0/items" || u.Query().Get("$select") != "id" {
				t.Fatal("cursor escaped collection")
			}
		}
	})
}

func TestAzureManagedResourceBindingA264(t *testing.T) {
	cfg := goodConfig()
	id := cfg.PrincipalIDs[0]
	path := "/subscriptions/" + cfg.SubscriptionID + "/resourceGroups/owned/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
	cfg.ManagedIdentityResources = map[string]string{id: path}
	raw, _ := json.Marshal(cfg)
	if _, err := DecodeConfig(raw); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{strings.Replace(path, cfg.SubscriptionID, cfg.TenantID, 1), path + "/../foreign", strings.Replace(path, "Microsoft.ManagedIdentity", "Microsoft.Compute", 1), path + "?api-version=other"} {
		cfg.ManagedIdentityResources = map[string]string{id: candidate}
		raw, _ := json.Marshal(cfg)
		if _, err := DecodeConfig(raw); err == nil {
			t.Fatal("foreign/malformed managed resource accepted")
		}
	}
}
