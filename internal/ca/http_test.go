package ca_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/ejbca"
	"trstctl.com/trstctl/internal/ca/entrust"
	"trstctl.com/trstctl/internal/ca/globalsign"
	"trstctl.com/trstctl/internal/ca/sectigo"
	"trstctl.com/trstctl/internal/ca/smallstep"
	"trstctl.com/trstctl/internal/ca/vaultpki"
	"trstctl.com/trstctl/internal/ca/venafi"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
)

func TestExternalCAHTTPDefaultsBlockSSRF(t *testing.T) {
	req := ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      externalCAHTTPTestCSR(t, "svc.external-ca.test"),
		DNSNames: []string{"svc.external-ca.test"},
		TTL:      time.Hour,
	}
	unsafeURL := "https://127.0.0.1:9443"
	tests := []struct {
		name string
		ca   ca.CA
	}{
		{name: "digicert", ca: digicert.New("digicert", unsafeURL, []byte("api-key"))},
		{name: "ejbca", ca: ejbca.New(ejbca.Config{Name: "ejbca", BaseURL: unsafeURL, Token: []byte("token"), CAName: "ca", CertificateProfile: "profile", EndEntityProfile: "entity", Password: []byte("password")})},
		{name: "entrust", ca: entrust.New(entrust.Config{Name: "entrust", BaseURL: unsafeURL, CAID: "ca-1"})},
		{name: "globalsign", ca: globalsign.New(globalsign.Config{Name: "globalsign", BaseURL: unsafeURL, APIKey: []byte("api-key"), APISecret: []byte("api-secret")})},
		{name: "sectigo", ca: sectigo.New(sectigo.Config{Name: "sectigo", BaseURL: unsafeURL, Login: "login", Password: []byte("password"), CustomerURI: "customer", OrgID: 1, CertType: 1})},
		{name: "smallstep", ca: smallstep.New(smallstep.Config{Name: "smallstep", BaseURL: unsafeURL, ProvisionerName: "provisioner", ProvisionerKey: []byte("provisioner-secret")})},
		{name: "vaultpki", ca: vaultpki.New(vaultpki.Config{Name: "vaultpki", BaseURL: unsafeURL, Token: []byte("token"), Mount: "pki", Role: "web"})},
		{name: "venafi", ca: venafi.New(venafi.Config{Name: "venafi", BaseURL: unsafeURL, AccessToken: []byte("token"), PolicyDN: `\VED\Policy\trstctl`})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.ca.Issue(context.Background(), req)
			if !errors.Is(err, netsec.ErrSSRFBlocked) {
				t.Fatalf("Issue error = %v, want ErrSSRFBlocked", err)
			}
		})
	}
}

func TestExternalCAPrivateEndpointAllowlistIsNarrow(t *testing.T) {
	privateURL := "https://10.20.30.40"
	if err := ca.ValidateExternalCAEndpoint("testca", privateURL, ca.HTTPClientConfig{}); !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatalf("unallowlisted private endpoint error = %v, want ErrSSRFBlocked", err)
	}
	allowPrivate := ca.HTTPClientConfig{AllowPrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if err := ca.ValidateExternalCAEndpoint("testca", privateURL, allowPrivate); err != nil {
		t.Fatalf("allowlisted private endpoint = %v, want allowed", err)
	}
	metadata := ca.HTTPClientConfig{AllowPrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}}
	if err := ca.ValidateExternalCAEndpoint("testca", "https://169.254.169.254", metadata); !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatalf("metadata allowlist error = %v, want ErrSSRFBlocked", err)
	}
}

func externalCAHTTPTestCSR(t *testing.T, dnsName string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: dnsName, DNSNames: []string{dnsName}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}
