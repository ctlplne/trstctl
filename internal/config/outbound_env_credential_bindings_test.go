// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const bindingTenant = "c8000000-0000-4000-8000-000000000001"

// CR-008: an env credential approval names the one tenant, the integrations and the
// exact origins it is for, in the config file or the JSON environment form.
func TestOutboundEnvCredentialBindingsLoadFromFileAndEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trstctl.json")
	body := `{"outbound_env_credential_bindings":[{"ref":"env:TRSTCTL_GRAPH_TOKEN_FILE","tenant_id":"` + bindingTenant + `",` +
		`"integrations":["azure_machine_identity"],"origins":["https://graph.microsoft.com"]}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(func(k string) string { return map[string]string{"TRSTCTL_CONFIG_FILE": path}[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.OutboundEnvCredentialBindings; len(got) != 1 || got[0].Ref != "env:TRSTCTL_GRAPH_TOKEN_FILE" || got[0].TenantID != bindingTenant ||
		strings.Join(got[0].Integrations, ",") != "azure_machine_identity" || strings.Join(got[0].Origins, ",") != "https://graph.microsoft.com" {
		t.Fatalf("file bindings = %+v", got)
	}

	env := map[string]string{ // #nosec G101 -- reference names only; no credential value (CWE-798)
		"TRSTCTL_CONFIG_FILE": path,
		"TRSTCTL_OUTBOUND_ENV_CREDENTIAL_BINDINGS": `[{"ref":"env:TRSTCTL_SPLUNK_TOKEN","tenant_id":"` + bindingTenant + `",` +
			`"integrations":["audit_feed","response_integration"],"origins":["https://hec.example:8088"]}]`,
	}
	cfg, err = Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load with env bindings: %v", err)
	}
	if got := cfg.OutboundEnvCredentialBindings; len(got) != 1 || got[0].Ref != "env:TRSTCTL_SPLUNK_TOKEN" || strings.Join(got[0].Integrations, ",") != "audit_feed,response_integration" {
		t.Fatalf("the environment did not replace the file's bindings: %+v", got)
	}
}

func TestOutboundEnvCredentialBindingsRefuseIncompleteApprovals(t *testing.T) {
	for name, raw := range map[string]string{
		"not JSON":           `env:TRSTCTL_SPLUNK_TOKEN`,
		"trailing data":      `[] []`,
		"misspelled field":   `[{"ref":"env:X","tenant":"` + bindingTenant + `","integrations":["audit_feed"],"origins":["https://hec.example"]}]`,
		"no tenant":          `[{"ref":"env:X","integrations":["audit_feed"],"origins":["https://hec.example"]}]`,
		"every tenant":       `[{"ref":"env:X","tenant_id":"*","integrations":["audit_feed"],"origins":["https://hec.example"]}]`,
		"no integration":     `[{"ref":"env:X","tenant_id":"` + bindingTenant + `","origins":["https://hec.example"]}]`,
		"unknown kind":       `[{"ref":"env:X","tenant_id":"` + bindingTenant + `","integrations":["webhook"],"origins":["https://hec.example"]}]`,
		"no origin":          `[{"ref":"env:X","tenant_id":"` + bindingTenant + `","integrations":["audit_feed"]}]`,
		"origin with a path": `[{"ref":"env:X","tenant_id":"` + bindingTenant + `","integrations":["audit_feed"],"origins":["https://hec.example/services"]}]`,
		"bare env name":      `[{"ref":"X","tenant_id":"` + bindingTenant + `","integrations":["audit_feed"],"origins":["https://hec.example"]}]`,
	} {
		_, err := Load(func(k string) string {
			return map[string]string{"TRSTCTL_OUTBOUND_ENV_CREDENTIAL_BINDINGS": raw}[k]
		})
		if err == nil {
			t.Errorf("%s: an incomplete binding was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "outbound_env_credential_bindings") && !strings.Contains(err.Error(), "TRSTCTL_OUTBOUND_ENV_CREDENTIAL_BINDINGS") {
			t.Errorf("%s: the error does not name the setting: %v", name, err)
		}
	}
}
