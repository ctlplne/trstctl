// SPDX-License-Identifier: BUSL-1.1
package gcpiam

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGCPSourceRejectsAmbiguousReferencesAndScopeA264(t *testing.T) {
	good := Config{Project: "owned-project", ServiceAccounts: []string{"orders@owned-project.iam.gserviceaccount.com"}, TokenFileRef: strings.Join([]string{"env", "OWNED_GCP_READER"}, ":"), ActivityLookbackDays: 30}
	raw, _ := json.Marshal(good)
	if _, err := DecodeConfig(raw); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){"path": func(c *Config) { c.TokenFileRef = "file:/owned/private" }, "inline": func(c *Config) { c.TokenFileRef = "owned-inline-token" }, "scope injection": func(c *Config) { c.Project = "owned-project/../../another" }, "duplicate account": func(c *Config) { c.ServiceAccounts = append(c.ServiceAccounts, c.ServiceAccounts[0]) }, "query email": func(c *Config) { c.ServiceAccounts = []string{"owned?evil@owned.iam.gserviceaccount.com"} }, "audit bound": func(c *Config) { c.ActivityLookbackDays = 91 }, "origin": func(c *Config) { c.IAMEndpoint = "https://iam.googleapis.com/another" }, "plaintext": func(c *Config) { c.IAMEndpoint = "http://127.0.0.1:1" }} {
		t.Run(name, func(t *testing.T) {
			cfg := good
			mutate(&cfg)
			raw, _ := json.Marshal(cfg)
			if _, err := DecodeConfig(raw); err == nil {
				t.Fatal("invalid source admitted")
			}
		})
	}
	for _, raw := range []string{`{"project":"owned-project","Project":"another"}`, `{"token_file_ref":"env:OWNED","Token_File_Ref":"env:OTHER"}`, `{"private_key":"inline"}`} {
		if _, err := DecodeConfig([]byte(raw)); err == nil {
			t.Fatal("ambiguous source fields admitted")
		}
	}
}
func TestGCPNativeKeyBindingRejectsForeignAccountsAndPreservesAliasesA264(t *testing.T) {
	now := time.Now().UTC()
	email, id := "orders@owned-project.iam.gserviceaccount.com", "123456789012345678901"
	for _, name := range []string{"projects/owned-project/serviceAccounts/" + email + "/keys/owned", "projects/123456789/serviceAccounts/" + id + "/keys/owned"} {
		if key, ok := boundKeyID(name, "owned-project", email, id); !ok || key != "owned" {
			t.Fatal("native resource alias rejected")
		}
	}
	for _, name := range []string{"projects/foreign-project/serviceAccounts/" + email + "/keys/owned", "projects/owned-project/serviceAccounts/another@owned-project.iam.gserviceaccount.com/keys/owned", "projects/owned-project/serviceAccounts/" + id + "/keys/owned?injected"} {
		if _, ok := boundKeyID(name, "owned-project", email, id); ok {
			t.Fatal("foreign or malformed key bound to selected account")
		}
	}
	key := Key{Name: "projects/owned-project/serviceAccounts/" + email + "/keys/owned", Type: "USER_MANAGED", ValidAfter: now.Add(-time.Hour), ValidBefore: now.Add(time.Hour)}
	if validateKeys([]Key{key}, "owned-project", email, id, now) != nil {
		t.Fatal("valid key rejected")
	}
	key.ValidAfter = now.Add(time.Hour)
	if validateKeys([]Key{key}, "owned-project", email, id, now) == nil {
		t.Fatal("future native key creation accepted")
	}
}
func FuzzGCPMachineSourceA264(f *testing.F) {
	f.Add([]byte(`{"project":"owned-project","service_accounts":["orders@owned-project.iam.gserviceaccount.com"],"token_file_ref":"env:OWNED_READER"}`))
	f.Add([]byte(`{"project":"one","Project":"two"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		_, _ = DecodeConfig(raw)
	})
}
func FuzzGCPInventoryRecordA264(f *testing.F) {
	f.Add([]byte(`{"version":1,"provider":"gcp-iam","identity":{"email":"orders@owned-project.iam.gserviceaccount.com","uniqueId":"123456789012345678901"},"source_origin":"https://iam.googleapis.com"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 512<<10 {
			return
		}
		_, _ = DecodeInventory(raw)
	})
}

func TestGCPHexKeyIDWithZeroA264(t *testing.T) {
	now := time.Now()
	email := "orders@owned-project.iam.gserviceaccount.com"
	key := Key{Name: "projects/owned-project/serviceAccounts/" + email + "/keys/0123456789abcdef0123456789abcdef01234567", Type: "USER_MANAGED", ValidAfter: now.Add(-time.Hour), ValidBefore: now.Add(time.Hour)}
	if err := validateKeys([]Key{key}, "owned-project", email, "123456789012345678901", now); err != nil {
		t.Fatal("native hexadecimal key ID rejected", err)
	}
	if _, ok := boundKeyID(key.Name, "owned-project", email, "123456789012345678901"); !ok {
		t.Fatal("native hexadecimal key ID failed audit binding")
	}
}
