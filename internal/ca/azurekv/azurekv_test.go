package azurekv_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/azurekv"
	"trstctl.com/trstctl/internal/ca/azurekv/azurekvfake"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func azurekvCSR(t *testing.T, cn string) []byte {
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

// TestPluginIssuesEndToEnd is the acceptance: the Azure Key Vault plugin issues a
// real certificate against a faithful Key Vault API double (create → operation →
// get).
func TestPluginIssuesEndToEnd(t *testing.T) {
	api, err := azurekvfake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	p := azurekv.New(azurekv.Config{Name: "azure-key-vault", VaultBaseURL: api.VaultBaseURL()}, api)
	if p.Name() != "azure-key-vault" {
		t.Errorf("Name = %q", p.Name())
	}
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: azurekvCSR(t, "svc.azurekv.test"), DNSNames: []string{"svc.azurekv.test"}, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "azure-key-vault" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.azurekv.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.azurekv.test", info.DNSNames)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Errorf("issued cert already expired: %s", info.NotAfter)
	}
}

// TestPluginPassesConformance: the Azure Key Vault plugin passes the shared
// CA-plugin conformance suite (S4.6).
func TestPluginPassesConformance(t *testing.T) {
	api, err := azurekvfake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	p := azurekv.New(azurekv.Config{Name: "azure-key-vault", VaultBaseURL: api.VaultBaseURL()}, api)
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("Azure Key Vault plugin failed conformance: %+v", report.Checks)
	}
}

// TestPollsWhileOperationInProgress: Key Vault issues asynchronously — the
// certificate operation is inProgress until completed. The plugin polls and
// ultimately succeeds.
func TestPollsWhileOperationInProgress(t *testing.T) {
	api, err := azurekvfake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	api.SetPendingPolls(2) // the operation stays inProgress for two poll calls

	p := azurekv.New(azurekv.Config{Name: "azure-key-vault", VaultBaseURL: api.VaultBaseURL()}, api, azurekv.WithPollInterval(time.Millisecond))
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: azurekvCSR(t, "pending.azurekv.test"), DNSNames: []string{"pending.azurekv.test"}, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue (operation in progress): %v", err)
	}
	if len(cert.CertificatePEM) == 0 {
		t.Error("no certificate after polling through the in-progress operation")
	}
}

// TestRejectsUnknownVault: a create against an unknown vault base URL is surfaced
// as an issuance error.
func TestRejectsUnknownVault(t *testing.T) {
	api, err := azurekvfake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	p := azurekv.New(azurekv.Config{Name: "azure-key-vault", VaultBaseURL: "https://nope.vault.azure.net"}, api)
	if _, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: azurekvCSR(t, "svc.azurekv.test"), DNSNames: []string{"svc.azurekv.test"}, TTL: 24 * time.Hour,
	}); err == nil {
		t.Error("Issue accepted an unknown vault")
	}
}
