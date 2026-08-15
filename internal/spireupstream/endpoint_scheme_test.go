// SPDX-License-Identifier: MPL-2.0

package spireupstream

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validateEndpointScheme runs the real Config.validate with only the endpoint
// varying, so these tests exercise the production validator rather than a copy.
func validateEndpointScheme(t *testing.T, endpoint string) error {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Config{Endpoint: endpoint, CAAuthorityID: "ca-1", TokenFile: tokenFile}
	return c.validate()
}

// TestUpstreamEndpointRefusesPlaintextToRemoteHosts is the regression guard for
// the trust-domain takeover defect. This endpoint is the SPIFFE trust domain's
// UPSTREAM AUTHORITY: whatever answers it decides what the entire trust domain
// accepts as a valid root. The config validator accepted plain http:// to any
// host, so anyone on the network path could answer instead and become that
// authority.
func TestUpstreamEndpointRefusesPlaintextToRemoteHosts(t *testing.T) {
	for _, endpoint := range []string{
		"http://upstream.example.com/api",
		"http://10.0.0.5:8080",
		"http://[2001:db8::1]/roots",
	} {
		err := validateEndpointScheme(t, endpoint)
		if err == nil {
			t.Errorf("plaintext endpoint %q was accepted; an on-path attacker could become the trust domain's upstream authority", endpoint)
			continue
		}
		if !strings.Contains(err.Error(), "https") {
			t.Errorf("refusal for %q should point at https, got: %v", endpoint, err)
		}
	}
}

// TestUpstreamEndpointAllowsHTTPSAndLoopback keeps the check honest: https must
// still work, and plaintext to loopback is fine because there is no network to
// be on-path of.
func TestUpstreamEndpointAllowsHTTPSAndLoopback(t *testing.T) {
	for _, endpoint := range []string{
		"https://upstream.example.com/api",
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://[::1]:8080",
	} {
		if err := validateEndpointScheme(t, endpoint); err != nil {
			t.Errorf("endpoint %q was refused: %v", endpoint, err)
		}
	}
}

// TestIsLoopbackHostRejectsLookalikes pins the helper: a hostname that merely
// mentions localhost is not loopback.
func TestIsLoopbackHostRejectsLookalikes(t *testing.T) {
	for _, host := range []string{"localhost.attacker.example", "notlocalhost", "127.0.0.1.attacker.example", ""} {
		if isLoopbackHost(host) {
			t.Errorf("%q was treated as loopback", host)
		}
	}
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if !isLoopbackHost(host) {
			t.Errorf("%q was not treated as loopback", host)
		}
	}
}
