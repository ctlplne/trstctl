// SPDX-License-Identifier: BUSL-1.1

package enroll_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A191: the HTTP renewal endpoint carries a host agent's roles over unchanged
// and refuses a CSR that asks for a role the certificate does not carry, naming
// it, instead of quietly signing without it.
func TestEnrollRenewalRefusesARoleTheCSRAsksFor(t *testing.T) {
	a, err := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tok, err := a.IssueBootstrapToken(ctx, tenantA, "")
	if err != nil {
		t.Fatal(err)
	}
	current, err := a.EnrollBootstrap(ctx, tok, newCSR(t, "agent-01"))
	if err != nil {
		t.Fatal(err)
	}
	peer := leafDER(t, current)
	asking := func(role string) []byte {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
			CommonName: "agent-01",
			URIs:       []string{mtls.AgentRoleSPIFFEID(tenantA, "agent-01", role)},
		}, key)
		if err != nil {
			t.Fatal(err)
		}
		return csr
	}
	if _, err := a.EnrollRenewal(ctx, [][]byte{peer}, asking(mtls.AgentRoleNetwork)); !errors.Is(err, enroll.ErrRenewalRoleNotGranted) {
		t.Fatalf("a CSR asking for the network role = %v, want ErrRenewalRoleNotGranted", err)
	}
	renewed, err := a.EnrollRenewal(ctx, [][]byte{peer}, asking(mtls.AgentRoleHost))
	if err != nil {
		t.Fatalf("a CSR asking for the role it holds was refused: %v", err)
	}
	if roles, err := mtls.AgentRolesFromClientCert(leafDER(t, renewed)); err != nil || !slices.Equal(roles, []string{mtls.AgentRoleHost}) {
		t.Fatalf("renewed roles = %v, %v; want host carried over", roles, err)
	}
}
