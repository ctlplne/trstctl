// SPDX-License-Identifier: BUSL-1.1

package venafi_test

import (
	"context"
	"net/http"
	"strings"
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

// OD-7: under a Venafi policy that revokes only by the certificate object's
// DN, a thumbprint revocation is refused; with revoke_by certificate_dn the
// plugin finds the object by the certificate's thumbprint and revokes it by
// that DN. Once the object holds a newer certificate, a revocation of the old
// one is refused rather than revoking the newer one by DN.
func TestPluginRevokesByCertificateDNOD7(t *testing.T) {
	srv, err := venafifake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.RevokeByDNOnly()
	client := venafi.WithHTTPClient(&http.Client{Timeout: 5 * time.Second})
	byThumbprint := venafi.New(venafi.Config{Name: "venafi", BaseURL: srv.URL(), AccessToken: []byte(srv.Token()), PolicyDN: srv.PolicyDN()}, client)
	byDN := venafi.New(venafi.Config{Name: "venafi", BaseURL: srv.URL(), AccessToken: []byte(srv.Token()), PolicyDN: srv.PolicyDN(),
		RevokeBy: venafi.RevokeByCertificateDN}, client)
	ctx := context.Background()
	issue := func(cn string) ca.Certificate {
		t.Helper()
		cert, err := byDN.Issue(ctx, ca.IssueRequest{TenantID: "t1", CSR: venafiCSR(t, cn), DNSNames: []string{cn}, TTL: 90 * 24 * time.Hour})
		if err != nil {
			t.Fatalf("Issue %s: %v", cn, err)
		}
		return cert
	}
	cert := issue("dn.venafi.test")
	if err := ca.RevokeThrough(ctx, byThumbprint, ca.RevokeRequest{TenantID: "t1", Serial: cert.Serial, CertificatePEM: cert.CertificatePEM, ReasonCode: 1}); err == nil {
		t.Fatal("a policy that revokes only by DN accepted a thumbprint revocation")
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := ca.RevokeThrough(ctx, byDN, ca.RevokeRequest{TenantID: "t1", Serial: cert.Serial, CertificatePEM: cert.CertificatePEM, ReasonCode: 1}); err != nil {
			t.Fatalf("revoke by DN, attempt %d: %v", attempt, err)
		}
	}
	revoked := srv.Revocations()
	if len(revoked) != 1 {
		t.Fatalf("Venafi revoked %v; want exactly the issued certificate's object", revoked)
	}
	for dn, reason := range revoked {
		if !strings.HasPrefix(dn, srv.PolicyDN()+`\dn.venafi.test`) || reason != 1 {
			t.Fatalf("revoked %s with reason %d; want the issued object with keyCompromise (1)", dn, reason)
		}
	}

	// The object moved on to a newer certificate: the old one is not
	// revoked through the object's DN.
	old := issue("renewed.venafi.test")
	dn, err := srv.Renew(old.CertificatePEM, venafiCSR(t, "renewed.venafi.test"))
	if err != nil {
		t.Fatal(err)
	}
	err = ca.RevokeThrough(ctx, byDN, ca.RevokeRequest{TenantID: "t1", Serial: old.Serial, CertificatePEM: old.CertificatePEM, ReasonCode: 4})
	if err == nil || !strings.Contains(err.Error(), "renewed") {
		t.Fatalf("revoking a replaced certificate by DN = %v; want it refused naming the renewal", err)
	}
	if _, done := srv.Revocations()[dn]; done {
		t.Fatal("the object's newer certificate was revoked in place of the one named")
	}
}
