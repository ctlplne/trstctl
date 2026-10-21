// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pqc"
)

// The CSR that leaves the host asserts the IP addresses its intent carries,
// for both subject key families; an unparseable address stops before any key
// is generated (A35).
func TestHostRenewalCSRCarriesBoundIPAddresses(t *testing.T) {
	for _, algorithm := range []string{"", string(pqc.MLDSA65)} {
		t.Run(algorithm, func(t *testing.T) {
			dir := t.TempDir()
			ch := &renewChannel{signErr: errors.New("stop before deployment")}
			ch.jobs = []relay.Job{renewJob(t, relay.DeployIntent{
				Connector: "nginx", Target: "host", SubjectKeyAlgorithm: algorithm,
				SubjectCommonName: "api.example.test", SubjectDNSNames: []string{"api.example.test"},
				SubjectIPAddresses: []string{"10.0.0.7", "2001:db8:0:0::1"},
				TargetConfig:       renewTargetConfig(t, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")),
			})}
			if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient, connector.LocalOpsConfig{AllowedRoots: []string{dir}}, 1, 60); err != nil {
				t.Fatal(err)
			}
			if ch.signCalls != 1 {
				t.Fatalf("sign calls = %d", ch.signCalls)
			}
			var info crypto.CSRInfo
			var err error
			if algorithm == "" {
				info, err = crypto.InspectCSR(ch.signed[0])
			} else {
				info, _, err = pqc.ParsePureMLDSACSR(ch.signed[0])
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(info.DNSNames) != 1 || len(info.IPAddresses) != 2 || info.IPAddresses[0] != "10.0.0.7" || info.IPAddresses[1] != "2001:db8::1" {
				t.Fatalf("CSR identifiers dns=%v ip=%v; want the bound DNS name and both addresses", info.DNSNames, info.IPAddresses)
			}
		})
	}
	t.Run("unparseable address", func(t *testing.T) {
		dir := t.TempDir()
		ch := &renewChannel{signErr: errors.New("stop before deployment")}
		ch.jobs = []relay.Job{renewJob(t, relay.DeployIntent{
			Connector: "nginx", Target: "host",
			SubjectCommonName: "api.example.test", SubjectDNSNames: []string{"api.example.test"},
			SubjectIPAddresses: []string{"10.0.0"},
			TargetConfig:       renewTargetConfig(t, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")),
		})}
		if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient, connector.LocalOpsConfig{AllowedRoots: []string{dir}}, 1, 60); err != nil {
			t.Fatal(err)
		}
		if ch.signCalls != 0 {
			t.Fatal("an intent with an unparseable IP address produced a CSR instead of failing closed")
		}
	})
}
