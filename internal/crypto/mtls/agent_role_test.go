// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
	"time"
)

// signWithRoles mints an agent certificate carrying roles and returns the leaf DER.
func signWithRoles(t *testing.T, ca *CA, cn, tenant string, roles []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	chainPEM, err := ca.SignClientCSRWithTenant(csrDER, tenant, roles, time.Hour)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	leafDER, err := FirstCertDER(chainPEM)
	if err != nil {
		t.Fatalf("first cert: %v", err)
	}
	return leafDER
}

// TestAgentRoleStampedByCANotCSR is the control this epic exists for: the
// capability in the issued certificate comes from the CALLER's grant, and a CSR
// that asks for a role of its own gets nothing for it.
func TestAgentRoleStampedByCANotCSR(t *testing.T) {
	ca, err := NewCA("test-agent-ca")
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	const tenant = "11111111-1111-1111-1111-111111111111"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// A CSR that puts the network role SAN in its own request. This is exactly the
	// self-promotion attempt the design refuses.
	selfClaimed, err := url.Parse(AgentRoleSPIFFEID(tenant, "greedy", AgentRoleNetwork))
	if err != nil {
		t.Fatalf("parse role uri: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "greedy"},
		URIs:    []*url.URL{selfClaimed},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}

	// The CA is told to grant host only.
	chainPEM, err := ca.SignClientCSRWithTenant(csrDER, tenant, []string{AgentRoleHost}, time.Hour)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	leafDER, err := FirstCertDER(chainPEM)
	if err != nil {
		t.Fatalf("first cert: %v", err)
	}
	roles, err := AgentRolesFromClientCert(leafDER)
	if err != nil {
		t.Fatalf("read roles: %v", err)
	}
	if len(roles) != 1 || roles[0] != AgentRoleHost {
		t.Fatalf("CSR-claimed network role survived into the certificate: got %v, want [host]", roles)
	}
}

// TestAgentCertWithoutRoleSANReadsAsHost pins the migration behaviour: every agent
// enrolled before roles existed keeps working, as a host agent, rather than being
// read as capability-less and stranded.
func TestAgentCertWithoutRoleSANReadsAsHost(t *testing.T) {
	ca, err := NewCA("test-agent-ca")
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	leafDER := signWithRoles(t, ca, "legacy-agent", "22222222-2222-2222-2222-222222222222", nil)
	roles, err := AgentRolesFromClientCert(leafDER)
	if err != nil {
		t.Fatalf("read roles: %v", err)
	}
	if len(roles) != 1 || roles[0] != AgentRoleHost {
		t.Fatalf("role-less certificate read as %v, want [host]", roles)
	}
}

// TestAgentRoleSANIsAdditive proves the identity SAN is unchanged by the presence
// of a role SAN — an older parser reading only the tenant SAN keeps working.
func TestAgentRoleSANIsAdditive(t *testing.T) {
	ca, err := NewCA("test-agent-ca")
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	const tenant = "33333333-3333-3333-3333-333333333333"
	leafDER := signWithRoles(t, ca, "relay-1", tenant, []string{AgentRoleNetwork, AgentRoleHost})

	gotTenant, err := TenantFromClientCert(leafDER)
	if err != nil {
		t.Fatalf("tenant from cert: %v", err)
	}
	if gotTenant != tenant {
		t.Fatalf("tenant attribution changed: got %q want %q", gotTenant, tenant)
	}
	roles, err := AgentRolesFromClientCert(leafDER)
	if err != nil {
		t.Fatalf("read roles: %v", err)
	}
	if len(roles) != 2 || roles[0] != AgentRoleHost || roles[1] != AgentRoleNetwork {
		t.Fatalf("roles = %v, want [host network]", roles)
	}
}

// TestSignClientCSRRefusesUnknownRole: a certificate carrying a role nothing reads
// is worse than no role, because it reads to an operator as a grant.
func TestSignClientCSRRefusesUnknownRole(t *testing.T) {
	ca, err := NewCA("test-agent-ca")
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "odd"},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	if _, err := ca.SignClientCSRWithTenant(csrDER, "44444444-4444-4444-4444-444444444444",
		[]string{"admin"}, time.Hour); err == nil {
		t.Fatal("signing accepted an unknown agent role")
	}
}
