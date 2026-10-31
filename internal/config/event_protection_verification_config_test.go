// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestEventProtectionHistoricalVerificationTrustIsExplicitAndOffline(t *testing.T) {
	cfg := Default()
	if cfg.Privacy.EventProtection.VerificationKeysFile != "" {
		t.Fatal("default config invented historical trust")
	}
	file := filepath.Join(t.TempDir(), "operator-pinned-public-jwks.json")
	wire, err := json.Marshal(map[string]any{"privacy": map[string]any{"event_protection": map[string]string{"verification_keys_file": file}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wire, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Privacy.EventProtection.VerificationKeysFile != file {
		t.Fatal("file config lost explicit public verification trust")
	}
	// The file intentionally does not exist: print/validate is offline and must
	// not read it. Actual runtime creation must refuse a missing configured file.
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(t.TempDir(), "replacement-public-jwks.json")
	cfg.applyEnv(func(name string) string {
		if name == "TRSTCTL_PRIVACY_EVENT_PROTECTION_VERIFICATION_KEYS_FILE" {
			return replacement
		}
		return ""
	})
	if cfg.Privacy.EventProtection.VerificationKeysFile != replacement {
		t.Fatal("environment did not override pinned public file")
	}
	if cfg.Privacy.EventProtection.KeyDirectory != "" {
		t.Fatal("public verification trust enabled or provisioned tenant custody")
	}
	for _, invalid := range []string{"relative/public.json", " /etc/trstctl/public.json", "/etc/trstctl/public.json "} {
		cfg.Privacy.EventProtection.VerificationKeysFile = invalid
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "privacy.event_protection.verification_keys_file") {
			t.Fatalf("invalid trust path accepted: %q %v", invalid, err)
		}
	}
}
