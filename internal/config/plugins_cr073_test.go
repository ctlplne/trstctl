// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

func TestCR073OperatorConfigRequiresCATenantNames(t *testing.T) {
	base := Plugins{Enabled: true, CADir: "/fixture/ca", TrustedKeyFiles: []string{"/fixture/trusted.pem"}}
	contains := func(errors []error, fragment string) bool {
		for _, err := range errors {
			if strings.Contains(err.Error(), fragment) {
				return true
			}
		}
		return false
	}
	if errs := base.validate(); !contains(errs, "ca_bindings") {
		t.Fatalf("unbound CA config errors = %v, want ca_bindings refusal", errs)
	}
	base.CABindings = map[string]PluginCABinding{
		"reference-ca": {TenantID: "11111111-1111-1111-1111-111111111111", AuthorityID: "22222222-2222-4222-8222-222222222222", DNSSuffixes: []string{"apps.example.test"}},
	}
	if errs := base.validate(); len(errs) != 0 {
		t.Fatalf("tenant-bound CA config errors = %v", errs)
	}
	base.CADir = ""
	if errs := base.validate(); !contains(errs, "ca_bindings requires plugins.ca_dir") {
		t.Fatalf("orphan CA binding errors = %v, want ca_dir refusal", errs)
	}
}
