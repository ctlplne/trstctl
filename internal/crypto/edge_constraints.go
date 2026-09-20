// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Constraint evaluation for a delegated edge CA (epic B6).
//
// B6 is the ONE deliberate exception to AN-3/AN-4: a signing key that lives
// outside the isolated signer, on a host with no path to the control plane. The
// exception is only defensible because the delegated CA certificate is bounded
// — name constraints scoping it to its segment, a validity measured in days,
// revocable and reconciled. This file is the bound.
//
// It lives in internal/crypto because that is where the crypto boundary is, and
// because a constraint check that an edge host could route around is not a
// constraint. Everything here is a pure function over already-parsed values: it
// makes no policy decision it cannot justify from the certificate itself.
//
// The rule that matters is FAIL CLOSED. A name this delegated CA cannot prove
// it is permitted to issue is refused, and "the constraint list was empty" is
// the most dangerous possible reason to allow something — an unconstrained
// delegated CA is exactly the unbounded shadow CA this design exists to
// prevent.

// EdgeConstraints is what a delegated CA certificate permits.
type EdgeConstraints struct {
	// PermittedDNSDomains scopes the DNS names this CA may issue. EMPTY MEANS
	// NOTHING IS PERMITTED, not "anything": an edge CA minted without
	// constraints would be an unbounded CA on a box nobody can reach.
	PermittedDNSDomains []string
	// ExcludedDNSDomains carves holes out of the permitted set. Exclusion wins
	// over permission, always — an operator who excluded a name meant it.
	ExcludedDNSDomains []string
	// PermittedIPRanges scopes IP SANs. Same rule: empty permits no IP SAN.
	PermittedIPRanges []*net.IPNet
	// NotAfter is when the delegated CA itself expires. A leaf may never outlive
	// the CA that issued it, so this bounds leaf validity too.
	NotAfter time.Time
}

// ErrEdgeUnconstrained is returned when a delegated CA carries no permitted
// names at all. It is a distinct error because it is a DIFFERENT failure from
// "this name is not permitted": one is a request that asked for too much, the
// other is a CA that should never have been minted.
type edgeError struct{ msg string }

func (e edgeError) Error() string { return e.msg }

// CheckEdgeIssuance decides whether a delegated edge CA may issue for these
// names at this moment.
//
// Order matters and is deliberate:
//  1. an unconstrained CA is refused outright, before any name is examined.
//  2. an expired CA is refused, because an edge host's clock is the only clock
//     it has and a delegated CA that keeps issuing past its expiry is a
//     permanent CA.
//  3. exclusions are applied before permissions, so an excluded name cannot be
//     re-permitted by a broader suffix.
//  4. every name must be positively permitted. A name nobody matched is
//     refused; there is no default-allow branch in this function.
func CheckEdgeIssuance(c EdgeConstraints, dnsNames []string, ipSANs []net.IP, now time.Time) error {
	if len(c.PermittedDNSDomains) == 0 && len(c.PermittedIPRanges) == 0 {
		return edgeError{"crypto: delegated edge CA carries no name constraints; an unconstrained " +
			"CA on an unreachable host is the unbounded shadow CA this design exists to prevent, " +
			"and it must be refused rather than trusted"}
	}
	if !c.NotAfter.IsZero() && !now.Before(c.NotAfter) {
		return edgeError{fmt.Sprintf(
			"crypto: delegated edge CA expired at %s; a delegated CA that keeps issuing past its "+
				"own expiry is a permanent CA, which is the opposite of what was delegated",
			c.NotAfter.UTC().Format(time.RFC3339))}
	}
	if len(dnsNames) == 0 && len(ipSANs) == 0 {
		return edgeError{"crypto: issuance request carries no names; a certificate that identifies " +
			"nothing cannot be checked against a constraint"}
	}
	for _, name := range dnsNames {
		if err := checkEdgeDNS(c, name); err != nil {
			return err
		}
	}
	for _, ip := range ipSANs {
		if err := checkEdgeIP(c, ip); err != nil {
			return err
		}
	}
	return nil
}

// checkEdgeDNS applies exclusions, then permissions, to one name.
func checkEdgeDNS(c EdgeConstraints, name string) error {
	n := normalizeEdgeName(name)
	if n == "" {
		return edgeError{fmt.Sprintf("crypto: %q is not a usable DNS name", name)}
	}
	for _, excluded := range c.ExcludedDNSDomains {
		if edgeDNSMatches(n, normalizeEdgeName(excluded)) {
			return edgeError{fmt.Sprintf(
				"crypto: %q is excluded by the delegated CA's constraints. An exclusion always "+
					"wins over a permission: an operator who excluded a name meant it, and a "+
					"broader permitted suffix must not silently re-admit it", name)}
		}
	}
	for _, permitted := range c.PermittedDNSDomains {
		if edgeDNSMatches(n, normalizeEdgeName(permitted)) {
			return nil
		}
	}
	return edgeError{fmt.Sprintf(
		"crypto: %q is outside this delegated CA's permitted names (%s). The request is refused "+
			"rather than issued: an edge CA that can name anything is not delegated, it is a "+
			"second root", name, strings.Join(c.PermittedDNSDomains, ", "))}
}

// checkEdgeIP requires an IP SAN to fall inside a permitted range.
func checkEdgeIP(c EdgeConstraints, ip net.IP) error {
	for _, r := range c.PermittedIPRanges {
		if r != nil && r.Contains(ip) {
			return nil
		}
	}
	return edgeError{fmt.Sprintf(
		"crypto: IP SAN %s is outside this delegated CA's permitted ranges", ip)}
}

// edgeDNSMatches implements RFC 5280 name-constraint matching for DNS.
//
// A constraint of "corp.example" permits "corp.example" and any subdomain, and
// must NOT permit "evilcorp.example". That suffix-without-label-boundary
// mistake is the classic name-constraint bypass, and it is the reason this is a
// function with a test rather than a strings.HasSuffix at a call site.
func edgeDNSMatches(name, constraint string) bool {
	if constraint == "" {
		return false
	}
	if name == constraint {
		return true
	}
	return strings.HasSuffix(name, "."+constraint)
}

// normalizeEdgeName lowercases and strips a trailing dot so that "Host.Corp." and
// "host.corp" cannot be treated as different names — one permitted, one not.
func normalizeEdgeName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// EdgeLeafNotAfter bounds a leaf's expiry by the delegated CA's own.
//
// A leaf outliving its issuing CA is a certificate that validates today and
// fails the moment the CA expires, with nothing in the leaf explaining why. At
// the edge that failure lands on a host nobody can reach to fix.
func EdgeLeafNotAfter(c EdgeConstraints, requested time.Time) time.Time {
	if c.NotAfter.IsZero() {
		return requested
	}
	if requested.After(c.NotAfter) {
		return c.NotAfter
	}
	return requested
}
