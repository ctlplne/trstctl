// SPDX-License-Identifier: MPL-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTransitKeyringDirConfig proves the documented `transit.keyring_dir` key
// parses from the config file and that TRSTCTL_TRANSIT_KEYRING_DIR overrides
// it. docs/limitations.md promised this key before it existed (AUD-201
// follow-up A1/V2): the persistence layer shipped with no way to turn it on.
func TestTransitKeyringDirConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trstctl.json")
	body := `{"transit":{"keyring_dir":"/var/lib/trstctl/transit"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	fileOnly := map[string]string{"TRSTCTL_CONFIG_FILE": path}
	cfg, err := Load(func(k string) string { return fileOnly[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Transit.KeyringDir != "/var/lib/trstctl/transit" {
		t.Fatalf("transit.keyring_dir from file = %q, want %q", cfg.Transit.KeyringDir, "/var/lib/trstctl/transit")
	}

	withEnv := map[string]string{
		"TRSTCTL_CONFIG_FILE":         path,
		"TRSTCTL_TRANSIT_KEYRING_DIR": "/env/override/transit",
	}
	cfg, err = Load(func(k string) string { return withEnv[k] })
	if err != nil {
		t.Fatalf("Load with env: %v", err)
	}
	if cfg.Transit.KeyringDir != "/env/override/transit" {
		t.Fatalf("TRSTCTL_TRANSIT_KEYRING_DIR override = %q, want %q", cfg.Transit.KeyringDir, "/env/override/transit")
	}

	unset, err := Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("Load default: %v", err)
	}
	if unset.Transit.KeyringDir != "" {
		t.Fatalf("default transit.keyring_dir = %q, want empty (durability is an explicit operator decision)", unset.Transit.KeyringDir)
	}
}
