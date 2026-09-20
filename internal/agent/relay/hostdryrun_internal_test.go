// SPDX-License-Identifier: BUSL-1.1

package relay

import "testing"

// HostConnectorKinds is an operator-facing capability census. Every advertised
// family must also have an effect-free preflight description; otherwise the API
// can queue a target test that this binary can deploy but cannot explain.
func TestEveryHostConnectorHasAPreflightPlan(t *testing.T) {
	target := HostTargetConfig{ // #nosec G101 -- KeystorePasswordRef is a secret-store locator, not credential material (CWE-798).
		CertPath: "/srv/trstctl/tls/site.crt", KeyPath: "/srv/trstctl/tls/site.key",
		CRTPath: "/srv/trstctl/tls/site.pem", ConfigPath: "/srv/trstctl/haproxy.cfg",
		Endpoint: "http://127.0.0.1:9901", SecretName: "edge-cert",
		Binding: "0.0.0.0:443", Store: "MY", AppID: "{00000000-0000-0000-0000-000000000001}",
		ImportDir:       "/srv/trstctl/iis-import",
		PostfixCertPath: "/srv/trstctl/postfix/server.crt", PostfixKeyPath: "/srv/trstctl/postfix/server.key",
		DovecotCertPath: "/srv/trstctl/dovecot/server.crt", DovecotKeyPath: "/srv/trstctl/dovecot/server.key",
		KeystorePath: "/srv/trstctl/java/identity.p12", KeystorePasswordRef: "secret://java/store-password",
		Alias: "identity", Format: "pkcs12",
	}
	seen := map[string]bool{}
	for _, kind := range HostConnectorKinds() {
		if seen[kind] {
			t.Fatalf("host connector census repeats %q", kind)
		}
		seen[kind] = true
		if _, err := hostPreflightActions(kind, target); err != nil {
			t.Errorf("advertised host connector %q has no usable preflight plan: %v", kind, err)
		}
	}
	if _, err := hostPreflightActions("future-connector", target); err == nil {
		t.Fatal("an unknown host connector received a generic passing preflight")
	}
}
