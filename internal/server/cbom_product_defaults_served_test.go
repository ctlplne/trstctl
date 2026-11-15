// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// X2-L7 served: a host-config scan reports the protocol and key-exchange group
// a product reaches only through its built-in default, by the version the
// host's package database records. A HAProxy 2.0 listener and an OpenSSL
// 1.1.1 configuration that state no minimum allow TLS 1.0 by default: the
// inventory lists both as defaults, out of policy, naming the packages. After
// the packages are upgraded (HAProxy 2.8, OpenSSL 3.5) a clean rescan retires
// those defaults and lists the new ones: TLS 1.2 and the hybrid
// X25519MLKEM768 group, which is not quantum vulnerable.
func TestServedCBOMHostScanReportsProductDefaultsX2L7(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "dpkg-status")
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(db, "Package: haproxy\nStatus: install ok installed\nVersion: 2.0.33-0ubuntu0.1\n\n"+
		"Package: libssl1.1\nStatus: install ok installed\nVersion: 1.1.1f-1ubuntu2.24\n")
	haproxy, openssl := filepath.Join(dir, "haproxy.cfg"), filepath.Join(dir, "openssl.cnf")
	write(haproxy, "frontend web\n  bind :443 ssl crt /etc/haproxy/site.pem\n  default_backend app\n")
	write(openssl, "openssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\n")

	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.CBOMPackageDatabases = []string{db} })
	// Its own tenant: its CBOM rows stay out of the shared served tenant's
	// other tests.
	const tenant = "a2070007-27a7-4a27-8a27-0000a2070007"
	registerServedTenantID(t, h, tenant, "X2-L7 product defaults tenant")
	token := seedScopedToken(t, h.store, tenant, "discovery:write", "risk:read")
	type item struct {
		Location          string `json:"location"`
		Protocol          string `json:"protocol"`
		Algorithm         string `json:"algorithm"`
		Library           string `json:"library"`
		OutOfPolicy       bool   `json:"out_of_policy"`
		QuantumVulnerable bool   `json:"quantum_vulnerable"`
		ConfigSource      string `json:"config_source"`
		ProductVersion    string `json:"product_version"`
	}
	scan := func(stage string) []string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/cbom/scans", token, map[string]any{"host_configs": []string{haproxy, openssl}})
		if status != http.StatusCreated {
			t.Fatalf("%s scan: status %d body %s", stage, status, body)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", token, nil)
		if status != http.StatusOK {
			t.Fatalf("%s inventory: status %d body %s", stage, status, body)
		}
		var inventory struct {
			Items []item `json:"items"`
		}
		if err := json.Unmarshal(body, &inventory); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, it := range inventory.Items {
			out = append(out, strings.Join([]string{filepath.Base(it.Location), it.Library, it.Protocol + it.Algorithm, it.ConfigSource,
				it.ProductVersion, map[bool]string{true: "out-of-policy", false: "in-policy"}[it.OutOfPolicy],
				map[bool]string{true: "quantum-vulnerable", false: "quantum-safe"}[it.QuantumVulnerable]}, "|"))
		}
		sort.Strings(out)
		return out
	}
	check := func(stage string, got, want []string) {
		t.Helper()
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("%s inventory:\n got %q\nwant %q", stage, got, want)
		}
	}
	check("legacy", scan("legacy"), []string{
		"haproxy.cfg|haproxy|TLSv1.0|default|haproxy 2.0.33-0ubuntu0.1|out-of-policy|quantum-safe",
		"haproxy.cfg|haproxy|X25519|default|libssl1.1 1.1.1f-1ubuntu2.24|in-policy|quantum-vulnerable",
		"openssl.cnf|openssl-config|TLSv1.0|default|libssl1.1 1.1.1f-1ubuntu2.24|out-of-policy|quantum-safe",
		"openssl.cnf|openssl-config|X25519|default|libssl1.1 1.1.1f-1ubuntu2.24|in-policy|quantum-vulnerable",
	})
	write(db, "Package: haproxy\nStatus: install ok installed\nVersion: 2.8.5-1ubuntu3\n\n"+
		"Package: libssl3\nStatus: install ok installed\nVersion: 3.5.9-1\n")
	check("upgraded", scan("upgraded"), []string{
		"haproxy.cfg|haproxy|TLSv1.2|default|haproxy 2.8.5-1ubuntu3|in-policy|quantum-safe",
		"haproxy.cfg|haproxy|X25519MLKEM768|default|libssl3 3.5.9-1|in-policy|quantum-safe",
		"openssl.cnf|openssl-config|TLSv1.2|default|libssl3 3.5.9-1|in-policy|quantum-safe",
		"openssl.cnf|openssl-config|X25519MLKEM768|default|libssl3 3.5.9-1|in-policy|quantum-safe",
	})
	t.Logf("X2L7_OK legacy defaults out of policy, upgraded defaults TLSv1.2 and X25519MLKEM768")
}
