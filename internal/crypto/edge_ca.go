// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// Minting a delegated edge CA (epic B6).
//
// This is the one place the platform hands a signing capability to a host it
// cannot reach. The certificate minted here is what an air-gapped segment uses
// to issue locally, so every bound that makes the delegation defensible has to
// be applied HERE, at mint time — an edge host cannot be asked to constrain
// itself, and a constraint added later cannot reach a CA already in the field.
//
// The default CA lifetime is five years. For a delegated edge CA that would be
// absurd: the whole argument for delegating is that the grant expires on its
// own while nobody is watching. So this path refuses to use the general
// default and requires a short one.

const (
	// maxEdgeCATTL bounds a delegated CA's life. Beyond a few weeks the
	// "temporary delegation" story stops being true, and a key on an
	// unreachable box becomes permanent by default.
	maxEdgeCATTL = 30 * 24 * time.Hour
	// defaultEdgeCATTL is used when a caller does not choose. Deliberately
	// short: an operator who did not think about lifetime gets the safe answer,
	// not the convenient one.
	defaultEdgeCATTL = 7 * 24 * time.Hour
)

// EdgeCARequest is a request to mint a delegated CA for one segment.
type EdgeCARequest struct {
	CommonName string
	// PermittedDNSDomains scopes what the edge CA may issue. REQUIRED — an
	// unconstrained delegated CA is a second root on a box nobody can reach.
	PermittedDNSDomains []string
	ExcludedDNSDomains  []string
	TTL                 time.Duration
}

// EdgeReportedLeaf is what the brain can verify about a leaf an edge host
// reports having issued: its identity and names, after the signature has been
// checked against the delegated CA that supposedly issued it.
type EdgeReportedLeaf struct {
	SerialHex string
	Subject   string
	DNSNames  []string
	IPSANs    []net.IP
	NotBefore time.Time
	NotAfter  time.Time
	DER       []byte
}

// InspectEdgeReportedLeaf parses a reported leaf and verifies its signature
// against the delegated CA's certificate. A leaf that does not chain is an
// error, not a record: reconciling it under this delegation would let anyone
// stuff another delegation's ledger with certificates it never issued.
func InspectEdgeReportedLeaf(delegationCertDER, leafDER []byte) (EdgeReportedLeaf, error) {
	delegation, err := x509.ParseCertificate(delegationCertDER)
	if err != nil {
		return EdgeReportedLeaf{}, fmt.Errorf("crypto: parse delegated CA certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return EdgeReportedLeaf{}, fmt.Errorf("crypto: parse reported leaf: %w", err)
	}
	if err := leaf.CheckSignatureFrom(delegation); err != nil {
		return EdgeReportedLeaf{}, fmt.Errorf("crypto: reported leaf was not issued by this delegated CA: %w", err)
	}
	return EdgeReportedLeaf{
		SerialHex: leaf.SerialNumber.Text(16),
		Subject:   leaf.Subject.String(),
		DNSNames:  append([]string(nil), leaf.DNSNames...),
		IPSANs:    append([]net.IP(nil), leaf.IPAddresses...),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		DER:       append([]byte(nil), leafDER...),
	}, nil
}

// EdgeAttestationChallenge derives the challenge an edge host's TPM
// attestation must sign to receive a delegated CA. It binds the attestation to
// this tenant, this segment, and THIS key (via the CSR bytes): an attestation
// captured for one segment cannot be replayed to widen another, and an
// attestation over someone else's key vouches for nothing. Both the brain and
// the agent derive it independently — it never travels.
func EdgeAttestationChallenge(tenantID, segmentID string, csrDER []byte) []byte {
	material := make([]byte, 0, len(tenantID)+len(segmentID)+len(csrDER)+32)
	material = append(material, []byte("trstctl-edge-delegation\x00")...)
	material = append(material, []byte(tenantID)...)
	material = append(material, 0)
	material = append(material, []byte(segmentID)...)
	material = append(material, 0)
	material = append(material, csrDER...)
	return SHA256Sum(material)
}

// MintDelegatedEdgeCAFromCSR is MintDelegatedEdgeCA for the served flow: the
// edge host generated its key locally (ideally in hardware) and sent only a
// CSR, so the delegated key never travels. The CSR's self-signature is the
// proof of possession; the certificate's contents come from the REQUEST the
// operator's policy built, never from the CSR's own asks — an edge host does
// not get to choose its own scope.
func MintDelegatedEdgeCAFromCSR(parentCertDER []byte, parentSigner DigestSigner, csrDER []byte, req EdgeCARequest) (IssuedHierarchyCA, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: parse edge CA CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: verify edge CA CSR signature: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: marshal edge CA CSR public key: %w", err)
	}
	if strings.TrimSpace(req.CommonName) == "" {
		req.CommonName = csr.Subject.CommonName
	}
	return MintDelegatedEdgeCA(parentCertDER, parentSigner, PublicKey{DER: pubDER}, req)
}

// MintDelegatedEdgeCA signs a name-constrained, short-lived delegated CA under
// the parent, using the parent's signer.
//
// The refusals are the product. Each one exists because the alternative is a
// signing key outside the isolated signer with a bound somebody forgot:
//   - NO CONSTRAINTS is refused outright. This is the difference between a
//     delegated CA and a second root.
//   - a TTL beyond the ceiling is refused rather than clamped. Silently
//     shortening what an operator asked for would leave them believing the
//     edge CA lives longer than it does, and planning renewals around a date
//     that is wrong.
//   - PATH LENGTH is pinned to zero: an edge CA may issue leaves and may never
//     mint another CA. A delegated CA that can delegate is an unbounded tree
//     rooted on an unreachable host.
func MintDelegatedEdgeCA(parentCertDER []byte, parentSigner DigestSigner, childPublic PublicKey, req EdgeCARequest) (IssuedHierarchyCA, error) {
	if len(req.PermittedDNSDomains) == 0 {
		return IssuedHierarchyCA{}, fmt.Errorf(
			"crypto: refusing to mint a delegated edge CA with no name constraints; that is not a " +
				"delegation, it is a second root on a host nobody can reach")
	}
	for _, d := range req.PermittedDNSDomains {
		if strings.TrimSpace(d) == "" {
			return IssuedHierarchyCA{}, fmt.Errorf(
				"crypto: a blank permitted domain would widen the constraint to everything")
		}
	}
	if strings.TrimSpace(req.CommonName) == "" {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: a delegated edge CA needs a common name")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = defaultEdgeCATTL
	}
	if ttl > maxEdgeCATTL {
		// Refused, not clamped: an operator told a shorter lifetime than they
		// asked for would plan renewals around a date that is wrong.
		return IssuedHierarchyCA{}, fmt.Errorf(
			"crypto: %s exceeds the %s ceiling for a delegated edge CA. The short life IS the "+
				"bound that makes delegating a signing key defensible; a longer one makes the key "+
				"permanent on a box nobody can reach", ttl, maxEdgeCATTL)
	}
	return SignIntermediateHierarchyCA(parentCertDER, parentSigner, childPublic, HierarchyCAProfile{
		CommonName:          strings.TrimSpace(req.CommonName),
		PermittedDNSDomains: append([]string(nil), req.PermittedDNSDomains...),
		ExcludedDNSDomains:  append([]string(nil), req.ExcludedDNSDomains...),
		// An edge CA issues leaves and never another CA.
		MaxPathLen: 0,
		TTL:        ttl,
	})
}
