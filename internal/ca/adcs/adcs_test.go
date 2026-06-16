package adcs_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/adcs"
	"trstctl.com/trstctl/internal/ca/adcs/adcsfake"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

const caConfig = `CA01.contoso.local\Contoso Issuing CA`

func adcsCSR(t *testing.T, cn string) []byte {
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

func config(name string) adcs.Config {
	return adcs.Config{Name: name, CAConfig: caConfig, Template: "WebServer"}
}

// TestPluginIssuesEndToEnd is the acceptance: the ADCS plugin issues a real
// certificate against a faithful MS-WCCE transport double (Request2 → issued).
func TestPluginIssuesEndToEnd(t *testing.T) {
	tr, err := adcsfake.NewTransport()
	if err != nil {
		t.Fatal(err)
	}
	p := adcs.New(config("adcs"), tr)
	if p.Name() != "adcs" {
		t.Errorf("Name = %q", p.Name())
	}
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: adcsCSR(t, "svc.adcs.test"), DNSNames: []string{"svc.adcs.test"}, TTL: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "adcs" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.adcs.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.adcs.test", info.DNSNames)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Errorf("issued cert already expired: %s", info.NotAfter)
	}
}

// TestPluginPassesConformance: the ADCS plugin passes the shared CA-plugin
// conformance suite (S4.6).
func TestPluginPassesConformance(t *testing.T) {
	tr, err := adcsfake.NewTransport()
	if err != nil {
		t.Fatal(err)
	}
	p := adcs.New(config("adcs"), tr)
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("ADCS plugin failed conformance: %+v", report.Checks)
	}
}

// TestPollsWhileUnderSubmission: ADCS may hold a request for manager approval
// (CR_DISP_UNDER_SUBMISSION). The plugin polls RetrievePending until issued.
func TestPollsWhileUnderSubmission(t *testing.T) {
	tr, err := adcsfake.NewTransport()
	if err != nil {
		t.Fatal(err)
	}
	tr.SetPendingPolls(2) // Request2 returns under-submission; two retrievals stay pending

	p := adcs.New(config("adcs"), tr, adcs.WithPollInterval(time.Millisecond))
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: adcsCSR(t, "pending.adcs.test"), DNSNames: []string{"pending.adcs.test"}, TTL: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue (under submission): %v", err)
	}
	if len(cert.CertificatePEM) == 0 {
		t.Error("no certificate after polling through under-submission")
	}
}

// TestDeniedRequestErrors: a request the policy module denies (CR_DISP_DENIED)
// surfaces as an issuance error rather than hanging.
func TestDeniedRequestErrors(t *testing.T) {
	tr, err := adcsfake.NewTransport()
	if err != nil {
		t.Fatal(err)
	}
	tr.SetDeny(true)

	p := adcs.New(config("adcs"), tr)
	if _, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: adcsCSR(t, "denied.adcs.test"), DNSNames: []string{"denied.adcs.test"}, TTL: 24 * time.Hour,
	}); err == nil {
		t.Error("Issue accepted a denied request")
	}
}
