// SPDX-License-Identifier: MPL-2.0

package server

import (
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca/venafi"
	"trstctl.com/trstctl/internal/ca/venafi/venafifake"
	"trstctl.com/trstctl/internal/config"
)

// TestServedExternalCARegistryIssuesViaVenafiTPPMock is the CLM-04 acceptance
// proof: a running control-plane binary serves the CLM-03 external-CA registry,
// selects a configured Venafi TPP/TLS Protect backend, submits a CSR to the
// upstream API mock, and returns a real certificate. This is the market-parity
// connector that was absent from the CA registry.
func TestServedExternalCARegistryIssuesViaVenafiTPPMock(t *testing.T) {
	tpp, err := venafifake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tpp.Close)

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = []ExternalCA{{
			ID:   "venafi",
			Type: "venafi-tpp",
			CA: venafi.New(venafi.Config{
				Name:        "venafi",
				BaseURL:     tpp.URL(),
				AccessToken: []byte(tpp.Token()),
				PolicyDN:    tpp.PolicyDN(),
				Application: "trstctl-served-test",
			}, venafi.WithHTTPClient(&http.Client{Timeout: 5 * time.Second})),
		}}
	})

	cert := issueExternalCA(t, h, "venafi", "svc.venafi.served.test", "clm-04-venafi")
	assertServedCert(t, cert, "venafi", "svc.venafi.served.test")
	if got := externalCAOutboxCount(t, h, "clm-04-venafi:external-ca:venafi"); got != 1 {
		t.Fatalf("Venafi ca.issue outbox rows = %d, want 1", got)
	}
}
