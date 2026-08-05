// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"fmt"
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
		// An edge CA issues leaves and never another CA.
		MaxPathLen: 0,
		TTL:        ttl,
	})
}
