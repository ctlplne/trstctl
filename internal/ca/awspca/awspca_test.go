package awspca_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/awspca"
	"trstctl.com/trstctl/internal/ca/awspca/awspcafake"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func awspcaCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: []string{cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestPluginIssuesEndToEnd is the acceptance: the AWS Private CA plugin issues a
// real certificate against a faithful acm-pca API double (IssueCertificate →
// GetCertificate).
func TestPluginIssuesEndToEnd(t *testing.T) {
	api, err := awspcafake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	p := awspca.New(awspca.Config{Name: "aws-private-ca", CertificateAuthorityArn: api.CAArn()}, api)
	if p.Name() != "aws-private-ca" {
		t.Errorf("Name = %q", p.Name())
	}
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: awspcaCSR(t, "svc.awspca.test"), DNSNames: []string{"svc.awspca.test"}, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "aws-private-ca" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.awspca.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.awspca.test", info.DNSNames)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Errorf("issued cert already expired: %s", info.NotAfter)
	}
}

// TestPluginPassesConformance: the AWS Private CA plugin passes the shared
// CA-plugin conformance suite (S4.6).
func TestPluginPassesConformance(t *testing.T) {
	api, err := awspcafake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	p := awspca.New(awspca.Config{Name: "aws-private-ca", CertificateAuthorityArn: api.CAArn()}, api)
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("AWS Private CA plugin failed conformance: %+v", report.Checks)
	}
}

// TestPollsWhileRequestInProgress: acm-pca issues asynchronously — GetCertificate
// raises RequestInProgressException until the certificate is ready. The plugin
// polls and ultimately succeeds.
func TestPollsWhileRequestInProgress(t *testing.T) {
	api, err := awspcafake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	api.SetPendingPolls(2) // first two GetCertificate calls report in-progress

	p := awspca.New(awspca.Config{Name: "aws-private-ca", CertificateAuthorityArn: api.CAArn()}, api, awspca.WithPollInterval(time.Millisecond))
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: awspcaCSR(t, "pending.awspca.test"), DNSNames: []string{"pending.awspca.test"}, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue (request in progress): %v", err)
	}
	if len(cert.CertificatePEM) == 0 {
		t.Error("no certificate after polling through RequestInProgress")
	}
}

// TestRejectsUnknownCA: an IssueCertificate against an unknown CA ARN is surfaced
// as an issuance error.
func TestRejectsUnknownCA(t *testing.T) {
	api, err := awspcafake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	p := awspca.New(awspca.Config{Name: "aws-private-ca", CertificateAuthorityArn: "arn:aws:acm-pca:us-east-1:000000000000:certificate-authority/does-not-exist"}, api)
	if _, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: awspcaCSR(t, "svc.awspca.test"), DNSNames: []string{"svc.awspca.test"}, TTL: 24 * time.Hour,
	}); err == nil {
		t.Error("Issue accepted an unknown CA ARN")
	}
}
