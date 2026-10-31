// SPDX-License-Identifier: BUSL-1.1

package sectigo_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/sectigo"
	"trstctl.com/trstctl/internal/ca/sectigo/sectigofake"
)

// A164: a revoke with a reason reaches SCM for the issued serial; SCM refuses a
// second revocation, and the plugin reads the certificate back as revoked so a
// retry changes nothing.
func TestPluginRevokesThroughSectigo(t *testing.T) {
	srv, err := sectigofake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	p := sectigo.New(config(srv), sectigo.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	ctx := context.Background()
	cert, err := p.Issue(ctx, ca.IssueRequest{
		TenantID: "t1", CSR: sectigoCSR(t, "svc.sectigo.test"), DNSNames: []string{"svc.sectigo.test"}, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !ca.CanRevoke("sectigo") {
		t.Fatal("the capability matrix does not say Sectigo can revoke")
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: cert.Serial, CertificatePEM: cert.CertificatePEM, ReasonCode: 1}); err != nil {
			t.Fatalf("revoke attempt %d: %v", attempt, err)
		}
		revoked := srv.Revocations()
		if len(revoked) != 1 {
			t.Fatalf("after attempt %d SCM revoked %v; want exactly the issued certificate", attempt, revoked)
		}
		for _, reason := range revoked {
			if reason != 1 {
				t.Fatalf("SCM recorded reason %d; want keyCompromise (1)", reason)
			}
		}
	}
	if err := ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: "0BADC0DE", ReasonCode: 1}); err == nil {
		t.Fatal("revoking a serial SCM never issued reported success")
	}
}
