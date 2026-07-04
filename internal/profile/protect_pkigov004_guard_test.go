// SPDX-License-Identifier: MPL-2.0

package profile

import (
	"testing"
	"time"
)

// PKIGOV-004 (19-PKIGOV) PROTECT regression guard.
//
// Confirmed strength: the served certificate-profile model encodes an RFC 5280 hygiene
// floor — allowed key algorithms, key-size floors (RSA/ECDSA), allowed EKUs, a maximum
// validity ceiling, allowed enrollment protocols, and DNS name-constraint suffixes —
// and CertificateProfile.Validate ENFORCES that floor by construction, rejecting a
// request that violates any of them with a descriptive error. Anchor:
// internal/profile/profile.go.
//
// This is a BEHAVIORAL test against the real exported Validate: it builds a strict
// profile and asserts a conforming request passes while each kind of violation is
// rejected. Pure in-memory logic — no Postgres, no signer, no network. If a future
// edit weakens any floor (e.g. stops checking the RSA-bit floor or the validity
// ceiling), the corresponding sub-assertion goes RED.
func TestProtectPKIGOV004_ProfileEnforcesHygieneFloor(t *testing.T) {
	const (
		minRSA   = 2048
		minECDSA = 256
		maxTTL   = 90 * 24 * time.Hour
	)
	p := CertificateProfile{
		Name:                 "rfc5280-floor",
		Version:              1,
		AllowedKeyAlgorithms: []string{"ECDSA", "RSA"},
		MinRSABits:           minRSA,
		MinECDSABits:         minECDSA,
		AllowedEKUs:          []string{"serverAuth", "clientAuth"},
		MaxValidity:          Duration(maxTTL),
		AllowedProtocols:     []string{"api", "acme"},
		AllowedDNSSuffixes:   []string{"example.com"},
	}

	// A fully conforming request passes (the floor permits compliant issuance).
	ok := Request{
		KeyAlgorithm:  "ECDSA",
		KeyBits:       256,
		RequestedEKUs: []string{"serverAuth"},
		TTL:           30 * 24 * time.Hour,
		DNSNames:      []string{"api.example.com"},
		Protocol:      "api",
	}
	if err := p.Validate(ok); err != nil {
		t.Fatalf("PKIGOV-004: a conforming request was rejected by the profile floor: %v", err)
	}

	cases := []struct {
		name string
		req  Request
		why  string
	}{
		{
			name: "rsa key below the size floor",
			req:  withBase(ok, func(r *Request) { r.KeyAlgorithm = "RSA"; r.KeyBits = 1024 }),
			why:  "a 1024-bit RSA key is below the 2048-bit floor and must be rejected",
		},
		{
			name: "ecdsa curve below the size floor",
			req:  withBase(ok, func(r *Request) { r.KeyAlgorithm = "ECDSA"; r.KeyBits = 192 }),
			why:  "a 192-bit ECDSA curve is below the 256-bit floor and must be rejected",
		},
		{
			name: "disallowed key algorithm",
			req:  withBase(ok, func(r *Request) { r.KeyAlgorithm = "DSA"; r.KeyBits = 2048 }),
			why:  "a key algorithm outside the allow-list must be rejected",
		},
		{
			name: "validity over the ceiling",
			req:  withBase(ok, func(r *Request) { r.TTL = maxTTL + time.Hour }),
			why:  "a TTL exceeding the max-validity ceiling must be rejected",
		},
		{
			name: "disallowed EKU",
			req:  withBase(ok, func(r *Request) { r.RequestedEKUs = []string{"codeSigning"} }),
			why:  "an EKU outside the allow-list must be rejected",
		},
		{
			name: "disallowed enrollment protocol",
			req:  withBase(ok, func(r *Request) { r.Protocol = "scep" }),
			why:  "an enrollment protocol outside the allow-list must be rejected",
		},
		{
			name: "DNS name outside the permitted suffix",
			req:  withBase(ok, func(r *Request) { r.DNSNames = []string{"api.evil.test"} }),
			why:  "a DNS name not under a permitted suffix must be rejected",
		},
		{
			name: "DNS suffix lookalike must not pass (label-boundary match)",
			req:  withBase(ok, func(r *Request) { r.DNSNames = []string{"api.notexample.com"} }),
			why:  "the suffix matcher must match on label boundaries, so notexample.com must NOT satisfy the example.com constraint",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := p.Validate(tc.req); err == nil {
				t.Fatalf("PKIGOV-004: %s — Validate returned nil (the hygiene floor is not being enforced)", tc.why)
			}
		})
	}
}

// withBase returns a copy of base mutated by fn, so each violation case differs from a
// known-good request in exactly one dimension.
func withBase(base Request, fn func(*Request)) Request {
	r := base
	// Copy slices so a case cannot alias another's backing array.
	r.RequestedEKUs = append([]string(nil), base.RequestedEKUs...)
	r.DNSNames = append([]string(nil), base.DNSNames...)
	fn(&r)
	return r
}
