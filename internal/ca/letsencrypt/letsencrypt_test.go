// SPDX-License-Identifier: BUSL-1.1

package letsencrypt_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/ca/letsencrypt/acmefake"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func newRemoteAccountPlugin(t *testing.T, name, directoryURL string) *letsencrypt.Plugin {
	t.Helper()
	account, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(account.Destroy)
	plugin, err := letsencrypt.NewPluginWithRemoteAccountSigner(name, directoryURL, http.DefaultClient, account)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plugin.Destroy)
	return plugin
}

func buildCSR(t *testing.T, cn string, dnsNames []string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: dnsNames}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestPluginIssuesRealCertEndToEnd is the acceptance: a real certificate is
// issued end-to-end through the (ACME / Let's Encrypt) plugin.
func TestPluginIssuesRealCertEndToEnd(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	p := newRemoteAccountPlugin(t, "lets-encrypt", srv.DirectoryURL())
	if p.Name() != "lets-encrypt" {
		t.Errorf("Name = %q", p.Name())
	}

	csr := buildCSR(t, "svc.acme.test", []string{"svc.acme.test"})
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: csr, DNSNames: []string{"svc.acme.test"}, TTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cert.Serial == "" || len(cert.CertificatePEM) == 0 || cert.Issuer != "lets-encrypt" {
		t.Fatalf("issued certificate = %+v", cert)
	}

	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.acme.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.acme.test", info.DNSNames)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Errorf("issued cert already expired: %s", info.NotAfter)
	}
	if info.SerialNumber != cert.Serial {
		t.Errorf("serial mismatch: cert %s vs result %s", info.SerialNumber, cert.Serial)
	}
}

// A production ACME account is intentionally long-lived. Real authorities
// answer a repeated newAccount request with HTTP 200 and x/crypto/acme returns
// ErrAccountAlreadyExists after caching the account URL. That response must not
// break the second certificate or a retry after a worker interruption.
func TestPluginReusesRegisteredAccountAcrossIssuance(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	p := newRemoteAccountPlugin(t, "lets-encrypt", srv.DirectoryURL())

	for _, name := range []string{"first.acme.test", "second.acme.test"} {
		cert, issueErr := p.Issue(context.Background(), ca.IssueRequest{
			TenantID: "t1", CSR: buildCSR(t, name, []string{name}), DNSNames: []string{name}, TTL: 24 * time.Hour,
		})
		if issueErr != nil {
			t.Fatalf("Issue(%s): %v", name, issueErr)
		}
		if cert.Serial == "" || len(cert.CertificatePEM) == 0 {
			t.Fatalf("Issue(%s) returned no certificate", name)
		}
	}
}

// Some conforming ACME authorities accept finalize asynchronously without
// repeating the order URL in a Location header. The client must reconcile the
// already-submitted order through the original order URL; submitting another
// order can mint a duplicate certificate.
func TestPluginReconcilesAsyncFinalizeWithoutLocation(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.EmulateAsyncFinalizeWithoutLocation()
	srv.RequireDomainValidation("async.acme.test", false)

	p := newSolvingPlugin(t, srv.DirectoryURL(), &recordingSolver{})
	name := "async.acme.test"
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: buildCSR(t, name, []string{name}), DNSNames: []string{name}, TTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cert.Serial == "" || len(cert.CertificatePEM) == 0 {
		t.Fatalf("reconciled issuance returned no certificate: %+v", cert)
	}
}
