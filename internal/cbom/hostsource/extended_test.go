// SPDX-License-Identifier: BUSL-1.1

package hostsource_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/hostsource"
)

// X2: HAProxy, Envoy, OpenSSL configuration and java.security each report the
// lowest protocol a statement explicitly allows, once per statement, and
// nothing for a version reached only through a product default.
func TestScanExtendedHostConfigProtocols(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"haproxy.cfg": "global\n  ssl-default-bind-options ssl-min-ver TLSv1.0 no-tls-tickets\n" +
			"  ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA\n" +
			"frontend web\n  bind :443 ssl crt /etc/haproxy/site.pem\n  bind :8443 ssl crt /etc/haproxy/b.pem force-tlsv12\n",
		"envoy.yaml": "common_tls_context:\n  tls_params:\n    tls_minimum_protocol_version: TLSv1_1\n" +
			"    cipher_suites:\n    - ECDHE-RSA-AES128-GCM-SHA256\n    - AES128-SHA\n",
		"openssl.cnf":   "[system_default_sect]\nMinProtocol = TLSv1\n",
		"java.security": "jdk.tls.disabledAlgorithms=SSLv3, TLSv1, RC4, DES, \\\n    MD5withRSA, DH keySize < 1024\n",
		"modern.cfg":    "global\n  ssl-default-bind-options no-sslv3\nfrontend f\n  bind :443 ssl crt /x.pem\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	protocols := func(name string) map[string]int {
		t.Helper()
		findings, err := hostsource.New(filepath.Join(dir, name)).Scan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]int{}
		for _, f := range findings {
			if f.Protocol != "" {
				out[f.Protocol+"|"+f.Library]++
			}
		}
		return out
	}
	weak := func(name string) int {
		t.Helper()
		findings, err := hostsource.New(filepath.Join(dir, name)).Scan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, f := range findings {
			if c := cbom.Classify(f, cbom.DefaultPolicy()); c.Strength == cbom.StrengthWeak {
				n++
			}
		}
		return n
	}
	if got := protocols("haproxy.cfg"); len(got) != 2 || got["TLSv1.0|haproxy"] != 1 || got["TLSv1.2|haproxy"] != 1 {
		t.Fatalf("haproxy protocols = %v, want one TLSv1.0 (ssl-min-ver) and one TLSv1.2 (force-tlsv12)", got)
	}
	// TLS 1.0 and the 3DES cipher are the weak facts.
	if got := weak("haproxy.cfg"); got != 2 {
		t.Fatalf("haproxy weak findings = %d, want 2 (TLSv1.0, DES-CBC3-SHA)", got)
	}
	if got := protocols("envoy.yaml"); len(got) != 1 || got["TLSv1.1|envoy"] != 1 {
		t.Fatalf("envoy protocols = %v", got)
	}
	if got := protocols("openssl.cnf"); len(got) != 1 || got["TLSv1.0|openssl-config"] != 1 {
		t.Fatalf("openssl.cnf protocols = %v", got)
	}
	if got := protocols("java.security"); len(got) != 1 || got["TLSv1.1|java-security"] != 1 {
		t.Fatalf("java.security protocols = %v, want TLSv1.1 (TLSv1 disabled, TLSv1.1 not)", got)
	}
	if got := protocols("modern.cfg"); len(got) != 0 {
		t.Fatalf("a HAProxy file with no explicit minimum claimed %v", got)
	}
}
