// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestAgentCredentialUsesOnlyTheEnrolledSubjectName(t *testing.T) {
	ca, err := NewCA("agent test authority")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "printer-1", OrganizationalUnit: []string{"Shipping"}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.SignClientCSRWithTenant(csr, "tenant-a", []string{AgentRoleHost}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	der, err := FirstCertDER(chain)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "printer-1" || len(cert.Subject.Names) != 1 {
		t.Errorf("agent subject = %v, want only the enrolled common name", cert.Subject)
	}
	roles, err := AgentRolesFromClientCert(der)
	if err != nil || len(roles) != 1 || roles[0] != AgentRoleHost {
		t.Fatalf("agent roles = %v, %v; want its granted host role", roles, err)
	}
}
