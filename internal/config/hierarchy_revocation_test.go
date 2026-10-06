// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

func TestHierarchyRevocationBaseURLValidationAndEnvironment(t *testing.T) {
	for _, base := range []string{"https://pki.example.test", "http://127.0.0.1:18443"} {
		cfg := Default()
		cfg.CA.HierarchyRevocationBaseURL = base
		if err := cfg.Validate(); err != nil {
			t.Errorf("valid managed CA status origin %q: %v", base, err)
		}
	}
	for _, base := range []string{"file:///etc/hosts", "https://user:pass@pki.example.test", "https://pki.example.test/wrong/path", "https://pki.example.test?redirect=other", "https://pki.example.test?", "https://pki.example.test/#fragment", "https://pki.example.test#", " https://pki.example.test", "https://pki.example.test ", "https://pki.example.test:bad", "https://pki.example.test:", "https://pki.example.test:0", "https://pki.example.test:65536"} {
		cfg := Default()
		cfg.CA.HierarchyRevocationBaseURL = base
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ca.hierarchy_revocation_base_url") {
			t.Errorf("unsafe managed CA status origin %q accepted: %v", base, err)
		}
	}
	var ca CA
	applyCAEnv(func(name string) string {
		if name == "TRSTCTL_CA_HIERARCHY_REVOCATION_BASE_URL" {
			return "https://env-pki.example.test"
		}
		return ""
	}, &ca)
	if ca.HierarchyRevocationBaseURL != "https://env-pki.example.test" {
		t.Fatalf("managed CA status env override = %q", ca.HierarchyRevocationBaseURL)
	}
}
