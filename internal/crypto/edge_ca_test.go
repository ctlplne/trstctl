// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func edgeParent(t *testing.T) (IssuedHierarchyCA, *LockedSigner, PublicKey) {
	t.Helper()
	parentSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parentSigner.Destroy)
	childSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(childSigner.Destroy)
	parent, err := SelfSignedHierarchyCA(parentSigner, HierarchyCAProfile{
		CommonName: "Edge Parent", PermittedDNSDomains: []string{"corp.example"},
		MaxPathLen: 2, EKUs: []string{"serverAuth"}, TTL: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return parent, parentSigner, childSigner.Public()
}

// An unconstrained delegated CA is a second root on a host nobody can reach.
func TestMintingRefusesAnUnconstrainedEdgeCA(t *testing.T) {
	t.Parallel()
	parent, signer, pub := edgeParent(t)
	_, err := MintDelegatedEdgeCA(parent.CertificateDER, signer, pub, EdgeCARequest{
		CommonName: "segment-a",
	})
	if err == nil {
		t.Fatal("a delegated edge CA was minted with NO name constraints.\n\n" +
			"That is not a delegation, it is a second root — on a box the platform cannot reach " +
			"to revoke.")
	}
	if !strings.Contains(err.Error(), "second root") {
		t.Errorf("the refusal does not explain what was nearly created: %v", err)
	}
	// A blank entry must not be treated as a constraint either.
	if _, err := MintDelegatedEdgeCA(parent.CertificateDER, signer, pub, EdgeCARequest{
		CommonName: "segment-a", PermittedDNSDomains: []string{"  "},
	}); err == nil {
		t.Fatal("a blank permitted domain was accepted; it widens the constraint to everything")
	}
}

// A too-long TTL is REFUSED, not clamped. Silently shortening leaves an
// operator planning renewals around a date that is wrong.
func TestATooLongEdgeCATTLIsRefusedNotClamped(t *testing.T) {
	t.Parallel()
	parent, signer, pub := edgeParent(t)
	_, err := MintDelegatedEdgeCA(parent.CertificateDER, signer, pub, EdgeCARequest{
		CommonName: "segment-a", PermittedDNSDomains: []string{"seg-a.corp.example"},
		TTL: 365 * 24 * time.Hour,
	})
	if err == nil {
		t.Fatal("a one-year delegated edge CA was minted.\n\n" +
			"The short life IS the bound that makes delegating a signing key defensible. Clamping " +
			"silently would be worse than refusing: the operator would plan renewals around a " +
			"date that is wrong.")
	}
	if !strings.Contains(err.Error(), "ceiling") {
		t.Errorf("the refusal does not name the ceiling: %v", err)
	}
}

// The minted certificate must actually carry the constraints and a path length
// of zero — an edge CA issues leaves and may never mint another CA.
func TestAMintedEdgeCACarriesItsConstraintsAndCannotDelegate(t *testing.T) {
	t.Parallel()
	parent, signer, pub := edgeParent(t)
	got, err := MintDelegatedEdgeCA(parent.CertificateDER, signer, pub, EdgeCARequest{
		CommonName: "segment-a", PermittedDNSDomains: []string{"seg-a.corp.example"},
		TTL: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(got.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.PermittedDNSDomains) == 0 {
		t.Fatal("the minted edge CA carries NO name constraints in the certificate itself.\n\n" +
			"A constraint that lives only in our records is not a constraint: the edge host " +
			"enforces what the certificate says, and nothing else.")
	}
	if !cert.MaxPathLenZero && cert.MaxPathLen != 0 {
		t.Fatalf("path length = %d; an edge CA that can mint another CA is an unbounded tree "+
			"rooted on an unreachable host", cert.MaxPathLen)
	}
	if d := time.Until(cert.NotAfter); d > maxEdgeCATTL+time.Hour {
		t.Fatalf("minted CA lives %v, past the %v ceiling", d, maxEdgeCATTL)
	}
}

// The default when a caller does not choose must be the SAFE answer.
func TestTheDefaultEdgeCALifetimeIsShort(t *testing.T) {
	t.Parallel()
	if defaultEdgeCATTL > maxEdgeCATTL {
		t.Fatal("the default exceeds the ceiling")
	}
	if defaultEdgeCATTL > 14*24*time.Hour {
		t.Fatalf("default = %v; an operator who did not think about lifetime must get the safe "+
			"answer, not the convenient one", defaultEdgeCATTL)
	}
	if defaultHierarchyCATTL <= maxEdgeCATTL {
		t.Fatal("the general CA default is within the edge ceiling, so this path would not need " +
			"its own bound — check that the edge path is still refusing the general default")
	}
}
