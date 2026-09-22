// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCBOMNativeProbeConfiguration(t *testing.T) {
	if got := cbomNativeConfiguredPath(t, Default()); got != "" {
		t.Fatalf("native execution enabled by default: %q", got)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"cbom":{"tls_probe_openssl":"/operator/openssl"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, env, want string }{
		{"file", "", "/operator/openssl"},
		{"environment overrides file", "/operator/other-openssl", "/operator/other-openssl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(func(key string) string {
				switch key {
				case "TRSTCTL_CONFIG_FILE":
					return path
				case "TRSTCTL_CBOM_TLS_PROBE_OPENSSL":
					return tc.env
				}
				return ""
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := cbomNativeConfiguredPath(t, cfg); got != tc.want {
				t.Fatalf("native path=%q want %q", got, tc.want)
			}
		})
	}
	for _, bad := range []string{"openssl", "./openssl", "/operator/openssl\x00extra"} {
		_, err := Load(func(key string) string {
			if key == "TRSTCTL_CBOM_TLS_PROBE_OPENSSL" {
				return bad
			}
			return ""
		})
		if err == nil || !strings.Contains(err.Error(), "cbom.tls_probe_openssl") {
			t.Fatalf("invalid path %q: %v", bad, err)
		}
	}
}

// Inspect the operator-facing serialized configuration so this regression can
// run against the preceding product, where the new field is silently ignored.
// A compile failure caused by referencing the proposed Go field is not RED proof.
func cbomNativeConfiguredPath(t *testing.T, cfg *Config) string {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		CBOM struct {
			Path string `json:"tls_probe_openssl"`
		} `json:"cbom"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	return wire.CBOM.Path
}
