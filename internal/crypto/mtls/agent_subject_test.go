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

	boundary "trstctl.com/trstctl/internal/crypto"
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
	t.Run("in-process issuer", func(t *testing.T) {
		chain, err := ca.SignClientCSRWithTenant(csr, "tenant-a", []string{AgentRoleHost}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		checkEnrolledAgentSubject(t, chain)
	})
	t.Run("digest signer used on the agent channel", func(t *testing.T) {
		key, err := boundary.GenerateLockedKey(boundary.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		caDER, err := boundary.SelfSignedCACert(key, "agent channel authority", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := boundary.SignAgentClientCSR(caDER, key, csr, AgentSPIFFEID("tenant-a", "printer-1"), []string{AgentRoleSPIFFEID("tenant-a", "printer-1", AgentRoleHost)}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		checkEnrolledAgentSubject(t, chain)
	})
}

func checkEnrolledAgentSubject(t *testing.T, chain []byte) {
	t.Helper()
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
