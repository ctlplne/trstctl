// SPDX-License-Identifier: BUSL-1.1

package hostsource_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/hostsource"
)

// Stock-style configurations: a HAProxy listener as its quick-start writes
// one (no minimum, no curves); a HAProxy file whose global section states
// both, as Debian's packaged haproxy.cfg does; an Envoy listener as its front
// proxy example writes one; and OpenSSL configurations with and without a
// system default section, as Debian's and Alpine's packaged openssl.cnf are.
var x2l7Configs = map[string]string{
	"haproxy-quickstart.cfg": "global\n  log /dev/log local0\ndefaults\n  mode http\nfrontend web\n  bind :443 ssl crt /etc/haproxy/site.pem\n" +
		"  default_backend app\nbackend app\n  server app1 10.0.0.10:8080\n",
	"haproxy-stated.cfg": "global\n  ssl-default-bind-curves X25519:P-256\n" +
		"  ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets\nfrontend web\n  bind :443 ssl crt /etc/haproxy/site.pem\n",
	"envoy-front-proxy.yaml": "static_resources:\n  listeners:\n  - name: https\n    filter_chains:\n    - transport_socket:\n" +
		"        name: envoy.transport_sockets.tls\n        typed_config:\n" +
		"          \"@type\": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext\n" +
		"          common_tls_context:\n            tls_certificates:\n            - certificate_chain: {filename: /etc/envoy/cert.pem}\n",
	"envoy-stated.yaml": "          \"@type\": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext\n" +
		"          common_tls_context:\n            tls_params:\n              tls_minimum_protocol_version: TLSv1_3\n" +
		"              ecdh_curves: [X25519MLKEM768]\n",
	"openssl.cnf": "openssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\n[provider_sect]\ndefault = default_sect\n",
	"openssl-seclevel0.cnf": "openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n[ssl_sect]\nsystem_default = sys\n[sys]\n" +
		"CipherString = DEFAULT:@SECLEVEL=0\n",
	"openssl-stated.cnf": "openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n[ssl_sect]\nsystem_default = sys\n[sys]\n" +
		"MinProtocol = TLSv1.2\nGroups = X25519MLKEM768:X25519\n",
}

// packageDB writes a dpkg status file or apk installed database fixture.
func packageDB(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func scanDefaults(t *testing.T, dir, config string, dbs ...string) []string {
	t.Helper()
	path := filepath.Join(dir, config)
	if err := os.WriteFile(path, []byte(x2l7Configs[config]), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := hostsource.New(path).WithPackageDatabases(dbs...).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range findings {
		if f.ConfigSource == "" {
			continue
		}
		c := cbom.Classify(f, cbom.DefaultPolicy())
		fact := f.Protocol + f.Algorithm
		out = append(out, strings.Join([]string{f.ConfigSource, f.Library, fact, f.ProductVersion, string(c.Strength), boolWord(c.QuantumVulnerable)}, "|"))
	}
	sort.Strings(out)
	return out
}

func boolWord(b bool) string {
	if b {
		return "quantum-vulnerable"
	}
	return "quantum-safe"
}

// TestHostConfigReportsProductDefaultsByVersionX2L7: a protocol or group a
// product reaches only through its built-in default is reported, marked
// default and naming the package and version whose default it is, by the
// version-keyed table: HAProxy before and from 2.2, Envoy before and from
// 1.22, OpenSSL before and from 3.1 (and @SECLEVEL=0), and OpenSSL's default
// groups before and from 3.5. A file that states its minimum and groups
// claims no default.
func TestHostConfigReportsProductDefaultsByVersionX2L7(t *testing.T) {
	dir := t.TempDir()
	ubuntu := packageDB(t, dir, "dpkg-status", "Package: haproxy\nStatus: install ok installed\nVersion: 2.8.5-1ubuntu3\n\n"+
		"Package: libssl3t64\nStatus: install ok installed\nVersion: 3.0.13-0ubuntu3.4\n\n"+
		"Package: getenvoy-envoy\nStatus: install ok installed\nVersion: 1.30.1.p0.g0e5ba65-1p5\n\n"+
		"Package: nginx\nStatus: deinstall ok config-files\nVersion: 1.24.0-2ubuntu7\n")
	alpine := packageDB(t, dir, "apk-installed", "P:haproxy\nV:3.0.5-r0\nA:aarch64\n\nP:libssl3\nV:3.5.9-r0\nA:aarch64\n")
	legacy := packageDB(t, dir, "dpkg-legacy", "Package: haproxy\nStatus: install ok installed\nVersion: 2.0.33-0ubuntu0.1\n\n"+
		"Package: libssl1.1\nStatus: install ok installed\nVersion: 1.1.1f-1ubuntu2.24\n\n"+
		"Package: envoy\nStatus: install ok installed\nVersion: 1.21.6-1\n")
	for _, tc := range []struct {
		config string
		db     string
		want   []string
	}{
		{"haproxy-quickstart.cfg", ubuntu, []string{
			"default|haproxy|TLSv1.2|haproxy 2.8.5-1ubuntu3|acceptable|quantum-safe",
			"default|haproxy|X25519|libssl3t64 3.0.13-0ubuntu3.4|acceptable|quantum-vulnerable"}},
		{"haproxy-quickstart.cfg", alpine, []string{
			"default|haproxy|TLSv1.2|haproxy 3.0.5-r0|acceptable|quantum-safe",
			"default|haproxy|X25519MLKEM768|libssl3 3.5.9-r0|strong|quantum-safe"}},
		{"haproxy-quickstart.cfg", legacy, []string{
			"default|haproxy|TLSv1.0|haproxy 2.0.33-0ubuntu0.1|weak|quantum-safe",
			"default|haproxy|X25519|libssl1.1 1.1.1f-1ubuntu2.24|acceptable|quantum-vulnerable"}},
		{"haproxy-stated.cfg", ubuntu, nil},
		{"envoy-front-proxy.yaml", ubuntu, []string{
			"default|envoy|TLSv1.2|getenvoy-envoy 1.30.1.p0.g0e5ba65-1p5|acceptable|quantum-safe",
			"default|envoy|X25519|getenvoy-envoy 1.30.1.p0.g0e5ba65-1p5|acceptable|quantum-vulnerable"}},
		{"envoy-front-proxy.yaml", legacy, []string{
			"default|envoy|TLSv1.0|envoy 1.21.6-1|weak|quantum-safe"}},
		{"envoy-stated.yaml", ubuntu, nil},
		{"openssl.cnf", alpine, []string{
			"default|openssl-config|TLSv1.2|libssl3 3.5.9-r0|acceptable|quantum-safe",
			"default|openssl-config|X25519MLKEM768|libssl3 3.5.9-r0|strong|quantum-safe"}},
		{"openssl.cnf", ubuntu, []string{
			"default|openssl-config|TLSv1.0|libssl3t64 3.0.13-0ubuntu3.4|weak|quantum-safe",
			"default|openssl-config|X25519|libssl3t64 3.0.13-0ubuntu3.4|acceptable|quantum-vulnerable"}},
		{"openssl-seclevel0.cnf", alpine, []string{
			"default|openssl-config|TLSv1.0|libssl3 3.5.9-r0|weak|quantum-safe",
			"default|openssl-config|X25519MLKEM768|libssl3 3.5.9-r0|strong|quantum-safe"}},
		{"openssl-stated.cnf", alpine, nil},
	} {
		got := scanDefaults(t, dir, tc.config, tc.db)
		if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
			t.Errorf("%s with %s:\n got %q\nwant %q", tc.config, filepath.Base(tc.db), got, tc.want)
		}
	}
}

// TestHostConfigClaimsNoDefaultWithoutAVersionX2L7: without a package database
// that records the product (an RPM host, a binary installed by hand, a
// removed package), no default is claimed: a default differs between
// releases, and a guess would be a false finding.
func TestHostConfigClaimsNoDefaultWithoutAVersionX2L7(t *testing.T) {
	dir := t.TempDir()
	removed := packageDB(t, dir, "dpkg-removed", "Package: haproxy\nStatus: deinstall ok config-files\nVersion: 2.8.5-1ubuntu3\n")
	for _, config := range []string{"haproxy-quickstart.cfg", "envoy-front-proxy.yaml", "openssl.cnf"} {
		for _, dbs := range [][]string{nil, {filepath.Join(dir, "absent")}, {removed}} {
			if got := scanDefaults(t, dir, config, dbs...); len(got) != 0 {
				t.Errorf("%s with %v claimed %q", config, dbs, got)
			}
		}
	}
}
