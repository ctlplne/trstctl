// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The type is canonical once the configuration loads, so validation and the
// issuance factory read the same value: "LetsEncrypt" in a config file used to
// pass validation (which lower-cased its own copy) and then fail at issuance
// ("unsupported external CA type").
func TestExternalCATypeIsCanonicalWhenConfigLoads(t *testing.T) {
	raw := []byte(`{"external_cas":[{"id":"le","type":" LetsEncrypt ","name":"Let's Encrypt","directory_url":"https://acme-v02.api.letsencrypt.org/directory"}]}`)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.ExternalCAs[0].Type; got != "letsencrypt" {
		t.Fatalf("Parse kept type %q; want letsencrypt", got)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(func(key string) string {
		if key == "TRSTCTL_CONFIG_FILE" {
			return path
		}
		return ""
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := loaded.ExternalCAs[0].Type; got != "letsencrypt" {
		t.Fatalf("Load kept type %q; want letsencrypt", got)
	}
	// A configuration built in code is validated as stored, as the factory
	// will read it.
	if err := ValidateExternalCAs([]ExternalCAConfig{{ID: "le", Type: "LetsEncrypt", Name: "le", DirectoryURL: "https://acme.example/directory"}}); err == nil ||
		!strings.Contains(err.Error(), "not a built-in external CA") {
		t.Fatalf("a non-canonical type built in code: %v; want it refused as the factory would", err)
	}
}
