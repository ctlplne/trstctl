// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestEventProtectionCustodyIsExplicitDefaultOffAndHasFileAndEnvironmentConfiguration(t *testing.T) {
	cfg := Default()
	if cfg.Privacy.EventProtection.KeyDirectory != "" {
		t.Fatal("default configuration invented event-key custody")
	}
	path := filepath.Join(t.TempDir(), "independent-keys")
	wire, err := json.Marshal(map[string]any{"privacy": map[string]any{"event_protection": map[string]string{"key_directory": path}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wire, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Privacy.EventProtection.KeyDirectory != path {
		t.Fatal("file configuration did not reach custody")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	override := filepath.Join(t.TempDir(), "other-keys")
	cfg.applyEnv(func(key string) string {
		if key == "TRSTCTL_PRIVACY_EVENT_PROTECTION_KEY_DIRECTORY" {
			return override
		}
		return ""
	})
	if cfg.Privacy.EventProtection.KeyDirectory != override {
		t.Fatal("environment did not override file configuration")
	}
	for _, bad := range []string{"relative/keys", " ../keys", " /tmp/keys ", "\t/tmp/keys"} {
		cfg.Privacy.EventProtection.KeyDirectory = bad
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "privacy.event_protection.key_directory") {
			t.Fatalf("invalid custody path accepted: %q %v", bad, err)
		}
	}
}
