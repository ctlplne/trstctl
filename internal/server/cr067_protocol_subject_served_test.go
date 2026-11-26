// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// The EST entry point is a second authorization route to the same signer.
// A bearer allowed to enroll a SAN must not create another DN identity.
func TestCR067ServedESTRefusesUnboundSubjectDN(t *testing.T) {
	h := newServedHarness(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
	registerServedTenant(t, h, "CR067 EST tenant")
	token := seedAPIToken(t, h.store, servedTestTenant)
	for _, tc := range []struct {
		name     string
		template crypto.CertificateRequestTemplate
	}{
		{"unbound-cn", crypto.CertificateRequestTemplate{CommonName: "postgres", DNSNames: []string{"device.example.test"}}},
		{"extra-rdn", crypto.CertificateRequestTemplate{CommonName: "device.example.test", DNSNames: []string{"device.example.test"}, Organization: []string{"system:masters"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			csr, err := crypto.CreateCertificateRequest(tc.template, key)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte(base64.StdEncoding.EncodeToString(csr))
			req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/.well-known/est/simpleenroll", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/pkcs10")
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := h.ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := readAllClose(resp); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode/100 == 2 {
				t.Fatalf("enrollment with unbound subject succeeded: %d", resp.StatusCode)
			}
		})
	}
}
