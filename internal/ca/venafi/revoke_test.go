// SPDX-License-Identifier: BUSL-1.1

package venafi_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/venafi"
	"trstctl.com/trstctl/internal/ca/venafi/venafifake"
)

// A164: a revoke with a reason reaches Venafi for the issued certificate (by its
// thumbprint), and retrying it changes nothing.
func TestPluginRevokesThroughVenafi(t *testing.T) {
	srv, err := venafifake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	p := venafi.New(venafi.Config{Name: "venafi", BaseURL: srv.URL(), AccessToken: []byte(srv.Token()), PolicyDN: srv.PolicyDN()},
		venafi.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	ctx := context.Background()
	cert, err := p.Issue(ctx, ca.IssueRequest{
		TenantID: "t1", CSR: venafiCSR(t, "svc.venafi.test"), DNSNames: []string{"svc.venafi.test"}, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !ca.CanRevoke("venafi") {
		t.Fatal("the capability matrix does not say Venafi can revoke")
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: cert.Serial, CertificatePEM: cert.CertificatePEM, ReasonCode: 4}); err != nil {
			t.Fatalf("revoke attempt %d: %v", attempt, err)
		}
		revoked := srv.Revocations()
		if len(revoked) != 1 {
			t.Fatalf("after attempt %d Venafi revoked %v; want exactly the issued certificate", attempt, revoked)
		}
		for _, reason := range revoked {
			if reason != 4 {
				t.Fatalf("Venafi recorded reason %d; want superseded (4)", reason)
			}
		}
	}
	if err := ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: cert.Serial, ReasonCode: 4}); err == nil {
		t.Fatal("a revocation without the certificate reached Venafi")
	}
}
