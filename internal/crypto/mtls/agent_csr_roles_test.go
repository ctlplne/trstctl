// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func csrAskingFor(t testing.TB, cn string, uris ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		req.URIs = append(req.URIs, u)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// A191: a renewal CSR's role SANs are read only so the renewal can refuse
// them. Every spiffe role segment is reported, unknown names included, so the
// refusal can name exactly what was asked; other URIs are not role requests.
func TestAgentRolesFromCSRReportsEveryRoleTheCSRAsksFor(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	der := csrAskingFor(t, "edge-1",
		AgentRoleSPIFFEID(tenant, "edge-1", AgentRoleNetwork),
		AgentRoleSPIFFEID(tenant, "edge-1", "admin"),
		AgentSPIFFEID(tenant, "edge-1"),
		"https://example.test/agent/edge-1/role/network")
	roles, err := AgentRolesFromCSR(der)
	if err != nil || !slices.Equal(roles, []string{AgentRoleNetwork, "admin"}) {
		t.Fatalf("roles asked for = %v, %v", roles, err)
	}
	if roles, err := AgentRolesFromCSR(csrAskingFor(t, "edge-1")); err != nil || len(roles) != 0 {
		t.Fatalf("an agent's own CSR asks for %v, %v", roles, err)
	}
	if _, err := AgentRolesFromCSR([]byte("not a csr")); err == nil {
		t.Fatal("a malformed CSR was read")
	}

	if got := AgentRolesBeyond([]string{AgentRoleNetwork, "admin", AgentRoleNetwork}, []string{AgentRoleHost}); !slices.Equal(got, []string{"admin", AgentRoleNetwork}) {
		t.Fatalf("roles beyond a host grant = %v", got)
	}
	if got := AgentRolesBeyond([]string{AgentRoleHost}, []string{AgentRoleHost, AgentRoleNetwork}); len(got) != 0 {
		t.Fatalf("a role the renewal signs was reported beyond it: %v", got)
	}
}

// The CSR is attacker-shaped input to the renewal path; reading its role
// requests never panics and never reports an empty or untrimmed role.
func FuzzAgentRolesFromCSR(f *testing.F) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	f.Add(csrAskingFor(f, "edge-1", AgentRoleSPIFFEID(tenant, "edge-1", AgentRoleNetwork)))
	f.Add(csrAskingFor(f, "edge-1", "spiffe://trstctl.local/tenant/x/agent/y/role/%20"))
	f.Add(csrAskingFor(f, "edge-1"))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		roles, err := AgentRolesFromCSR(der)
		if err != nil {
			return
		}
		for _, role := range roles {
			if role == "" || role != strings.TrimSpace(role) {
				t.Fatalf("reported role %q", role)
			}
		}
	})
}
