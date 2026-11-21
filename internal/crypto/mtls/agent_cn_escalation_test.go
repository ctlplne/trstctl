// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"testing"
	"time"

	boundary "trstctl.com/trstctl/internal/crypto"
)

// TestAgentCommonNameCannotForgeRoleSegments is the regression guard for the
// agent role-escalation defect. The CSR's common name is interpolated into the
// agent's SPIFFE ID as a PATH SEGMENT, and capability roles are encoded as
// further segments of that same path. A CN of "agent1/role/network" therefore
// produced spiffe://…/agent/agent1/role/network, which AgentRolesFromClientCert
// reads back as a `network` grant — so an agent issued a host-only bootstrap
// token could self-grant relay capability just by choosing its own CSR subject.
func TestAgentCommonNameCannotForgeRoleSegments(t *testing.T) {
	for _, cn := range []string{
		"agent1/role/network",
		"agent1/role/" + AgentRoleNetwork,
		"a/b",
		"agent1%2Frole%2Fnetwork",
		"agent1\\role\\network",
		"agent1?x=1",
		"agent1#frag",
	} {
		if err := ValidateAgentCommonName(cn); err == nil {
			t.Errorf("common name %q was accepted; it can forge SPIFFE path segments", cn)
		}
	}

	// Empty, padded and control-character subjects are refused too.
	for _, cn := range []string{"", "   ", " agent1", "agent1 ", "agent\x001"} {
		if err := ValidateAgentCommonName(cn); err == nil {
			t.Errorf("common name %q was accepted", cn)
		}
	}
}

// TestAgentCommonNameAcceptsOrdinarySubjects keeps the guard honest: real agent
// names must still enroll, so the check cannot be a blanket refusal.
func TestAgentCommonNameAcceptsOrdinarySubjects(t *testing.T) {
	for _, cn := range []string{
		"agent1",
		"web-01.corp.example",
		"agent_1",
		"agent.eu-west-1.prod",
		"AGENT-42",
	} {
		if err := ValidateAgentCommonName(cn); err != nil {
			t.Errorf("ordinary agent name %q was refused: %v", cn, err)
		}
	}
}

// Certificates minted before the served issuer used the common-name guard must
// not keep a forged capability alive through a channel connection or renewal.
func TestPreviouslyIssuedRolePathCertificateIsRejected(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	const forgedName = "host-a/role/network"
	caKey, err := boundary.GenerateLockedKey(boundary.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := boundary.SelfSignedCACert(caKey, "legacy agent CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := boundary.GenerateLockedKey(boundary.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer agentKey.Destroy()
	csr, err := boundary.CreateCertificateRequest(boundary.CertificateRequestTemplate{CommonName: forgedName}, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := boundary.SignAgentClientCSR(caDER, caKey, csr, AgentSPIFFEID(tenant, forgedName), nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := FirstCertDER(chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PeerCertInfoFromDER(leafDER); err == nil {
		t.Fatal("channel accepted a previously issued agent certificate with forged role segments")
	}
	if _, err := AgentRolesFromClientCert(leafDER); err == nil {
		t.Fatal("role reader accepted a previously issued agent certificate with forged role segments")
	}
}
