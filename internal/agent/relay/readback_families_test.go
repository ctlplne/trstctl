// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/a10/a10test"
	"trstctl.com/trstctl/internal/connector/kemp/kemptest"
	"trstctl.com/trstctl/internal/connector/netscaler/netscalertest"
)

// The relay asks a readback-capable family's device what it installed right
// after a deploy (epic E2). Kemp, NetScaler and A10 were listed as
// readback-capable while their connectors had no Readback, so every relay
// deploy to them reported "the appliance did not answer a readback": a
// sentence about an appliance nothing had asked. Each now answers with what
// the device reports.
func TestApplianceReadbackAsksKempNetScalerAndA10(t *testing.T) {
	cert := []byte("-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----")
	key := []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----")
	const user, pass, token = "svc-trstctl", "appliance-secret", "appliance-token"
	cases := []struct {
		family, target string
		start          func(t *testing.T) (string, *http.Client, Material, TargetConfig)
		want           connector.ReadbackVerdict
	}{
		{"kemp", "vs-payments-443", func(t *testing.T) (string, *http.Client, Material, TargetConfig) {
			srv := kemptest.New(token)
			t.Cleanup(srv.Close)
			return srv.URL(), srv.Client(), Material{"credential.kemp_token": []byte(token)},
				TargetConfig{TokenRef: "credential.kemp_token"} // #nosec G101 -- a credential reference name, not a credential (CWE-798)
		}, connector.ReadbackServing},
		// No SSL vserver uses the certkey in the double, so the certificate is
		// installed and serves nothing: that is what the device says.
		{"netscaler", "certkey-app", func(t *testing.T) (string, *http.Client, Material, TargetConfig) {
			srv := netscalertest.New(user, pass)
			t.Cleanup(srv.Close)
			return srv.URL(), srv.Client(), Material{"credential.ns_password": []byte(pass)},
				TargetConfig{Username: user, PasswordRef: "credential.ns_password"} // #nosec G101 -- a credential reference name, not a credential (CWE-798)
		}, connector.ReadbackInstalledNotBound},
		{"a10", "payments-client-ssl", func(t *testing.T) (string, *http.Client, Material, TargetConfig) {
			srv := a10test.New(user, pass)
			t.Cleanup(srv.Close)
			return srv.URL(), srv.Client(), Material{"credential.a10_password": []byte(pass)},
				TargetConfig{Username: user, PasswordRef: "credential.a10_password"} // #nosec G101 -- a credential reference name, not a credential (CWE-798)
		}, connector.ReadbackServing},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			endpoint, client, material, cfg := tc.start(t)
			cfg.Endpoint = endpoint
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			material["credential.cert_pem"] = cert
			material["credential.key_pem"] = key
			intent := DeployIntent{Connector: tc.family, Target: tc.target, TargetConfig: raw, Fingerprint: connector.CertificateFingerprint(cert)}
			if _, err := Execute(context.Background(), client, intent, material); err != nil {
				t.Fatalf("relay deploy: %v", err)
			}
			verdict, sentence := applianceReadback(context.Background(), client, intent, material)
			if verdict != tc.want || sentence == "" || strings.Contains(sentence, "did not answer") {
				t.Fatalf("readback after a relay deploy = %q %q, want %q from the device", verdict, sentence, tc.want)
			}
		})
	}
}
