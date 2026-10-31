// SPDX-License-Identifier: BUSL-1.1

package digicert_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
)

// A164: a revoke with a reason reaches CertCentral for the order whose
// certificate has the serial; the order reads back revoked, a retry changes
// nothing, and a request left waiting for an approver is not reported revoked.
func TestPluginRevokesThroughCertCentral(t *testing.T) {
	srv, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	p := digicert.New("digicert", srv.URL(), []byte(srv.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	ctx := context.Background()
	issue := func(name string) ca.Certificate {
		t.Helper()
		cert, err := p.Issue(ctx, ca.IssueRequest{TenantID: "t1", CSR: digicertCSR(t, name), DNSNames: []string{name}, TTL: 90 * 24 * time.Hour})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		return cert
	}
	if !ca.CanRevoke("digicert") {
		t.Fatal("the capability matrix does not say DigiCert can revoke")
	}
	cert := issue("svc.digicert.test")
	for attempt := 1; attempt <= 2; attempt++ {
		if err := ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: cert.Serial, ReasonCode: 1}); err != nil {
			t.Fatalf("revoke attempt %d: %v", attempt, err)
		}
		revoked := srv.Revocations()
		if len(revoked) != 1 {
			t.Fatalf("after attempt %d CertCentral revoked %v; want exactly the issued certificate", attempt, revoked)
		}
		for _, reason := range revoked {
			if reason != "key_compromise" {
				t.Fatalf("CertCentral recorded %q; want key_compromise", reason)
			}
		}
	}

	srv.RequireRevocationApproval(true)
	held := issue("held.digicert.test")
	err = ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: held.Serial, ReasonCode: 4})
	if err == nil || !strings.Contains(err.Error(), "waiting for approval") {
		t.Fatalf("a revocation waiting for an approver = %v; want it reported not yet revoked", err)
	}
	if len(srv.Revocations()) != 1 {
		t.Fatalf("a held request revoked a certificate: %v", srv.Revocations())
	}
}
