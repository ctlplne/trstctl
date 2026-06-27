// Package profile is trstctl's certificate-profile model (S8.1, F53): the
// versioned, fine-grained rules that govern what a certificate may be — allowed
// key types/sizes, EKUs, name constraints, validity ceilings, and which enrollment
// protocols may use the profile. Every issuance path validates a request against
// its bound profile BEFORE anything is signed.
//
// This package is deliberately free of crypto/x509 (AN-3): callers inspect a CSR
// through internal/crypto (CSRInfo) and pass the backend-agnostic attributes here.
package profile

import (
	"fmt"
	"strings"
	"time"
)

// ACMEAuthMode selects how an ACME profile proves identifier control.
type ACMEAuthMode string

const (
	// ACMEAuthModePublicTrust keeps full ACME DV challenge validation. It is the
	// fail-closed default for trstctl because a missing profile knob must not turn
	// a public CA endpoint into an internal trust endpoint.
	ACMEAuthModePublicTrust ACMEAuthMode = "public_trust"
	// ACMEAuthModeTrustAuthenticated lets an already authenticated internal ACME
	// account move directly to a ready order. It is only for internal PKI profiles.
	ACMEAuthModeTrustAuthenticated ACMEAuthMode = "trust_authenticated"
)

// CertificateProfile is one immutable, versioned profile. A new edit is a new
// Version; prior versions remain resolvable (S8.1 acceptance).
type CertificateProfile struct {
	Name    string `json:"name"`
	Version int    `json:"version"`

	RequiresApproval     bool         `json:"requires_approval,omitempty"` // profile create/edit and future issuance require dual control
	AllowedKeyAlgorithms []string     `json:"allowed_key_algorithms"`      // e.g. ["ECDSA","RSA"]; empty = any
	MinRSABits           int          `json:"min_rsa_bits"`                // floor for RSA keys; 0 = no floor
	MinECDSABits         int          `json:"min_ecdsa_bits"`              // floor for ECDSA curve size
	AllowedEKUs          []string     `json:"allowed_ekus"`                // e.g. ["serverAuth","clientAuth"]; empty = any
	MaxValidity          Duration     `json:"max_validity"`                // validity ceiling; 0 = no ceiling
	AllowedProtocols     []string     `json:"allowed_protocols"`           // enrollment protocols permitted; empty = any
	ACMEAuthMode         ACMEAuthMode `json:"acme_auth_mode,omitempty"`    // public_trust (default) or trust_authenticated
	AllowedDNSSuffixes   []string     `json:"allowed_dns_suffixes"`        // name constraint; empty = unconstrained
}

// NormalizeACMEAuthMode returns the explicit mode, defaulting empty to
// public_trust. Unknown values are rejected instead of silently widening trust.
func NormalizeACMEAuthMode(mode ACMEAuthMode) (ACMEAuthMode, error) {
	switch m := ACMEAuthMode(strings.TrimSpace(string(mode))); m {
	case "":
		return ACMEAuthModePublicTrust, nil
	case ACMEAuthModePublicTrust, ACMEAuthModeTrustAuthenticated:
		return m, nil
	default:
		return "", fmt.Errorf("profile: unsupported acme_auth_mode %q", mode)
	}
}

// Request is the backend-agnostic view of an issuance request to validate.
type Request struct {
	KeyAlgorithm  string        // from internal/crypto.CSRInfo
	KeyBits       int           // from internal/crypto.CSRInfo
	RequestedEKUs []string      // EKUs the caller asks for
	TTL           time.Duration // requested validity
	DNSNames      []string      // SANs
	Protocol      string        // "api" | "acme" | "est" | "scep" | "cmp" | ...
}

// Validate returns nil if r satisfies p, or a descriptive error naming the first
// violation (so a rejection has a clear reason — S8.1 acceptance). It enforces by
// construction, never "best effort".
func (p CertificateProfile) Validate(r Request) error {
	id := fmt.Sprintf("profile %q v%d", p.Name, p.Version)

	if len(p.AllowedProtocols) > 0 && r.Protocol != "" && !contains(p.AllowedProtocols, r.Protocol) {
		return fmt.Errorf("%s does not permit enrollment protocol %q", id, r.Protocol)
	}
	if len(p.AllowedKeyAlgorithms) > 0 && !contains(p.AllowedKeyAlgorithms, r.KeyAlgorithm) {
		return fmt.Errorf("%s does not allow key algorithm %q (allowed: %s)", id, r.KeyAlgorithm, strings.Join(p.AllowedKeyAlgorithms, ", "))
	}
	switch r.KeyAlgorithm {
	case "RSA":
		if p.MinRSABits > 0 && r.KeyBits < p.MinRSABits {
			return fmt.Errorf("%s requires RSA keys of at least %d bits, got %d", id, p.MinRSABits, r.KeyBits)
		}
	case "ECDSA":
		if p.MinECDSABits > 0 && r.KeyBits < p.MinECDSABits {
			return fmt.Errorf("%s requires ECDSA curves of at least %d bits, got %d", id, p.MinECDSABits, r.KeyBits)
		}
	}
	for _, eku := range r.RequestedEKUs {
		if len(p.AllowedEKUs) > 0 && !contains(p.AllowedEKUs, eku) {
			return fmt.Errorf("%s does not allow extended key usage %q (allowed: %s)", id, eku, strings.Join(p.AllowedEKUs, ", "))
		}
	}
	if p.MaxValidity > 0 && r.TTL > time.Duration(p.MaxValidity) {
		return fmt.Errorf("%s caps validity at %s, requested %s", id, time.Duration(p.MaxValidity), r.TTL)
	}
	for _, dns := range r.DNSNames {
		if len(p.AllowedDNSSuffixes) > 0 && !suffixAllowed(dns, p.AllowedDNSSuffixes) {
			return fmt.Errorf("%s does not permit DNS name %q (allowed suffixes: %s)", id, dns, strings.Join(p.AllowedDNSSuffixes, ", "))
		}
	}
	return nil
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// suffixAllowed reports whether dns is permitted by one of the configured
// suffixes, matching on label boundaries only (RFC 5280 §4.2.1.10 dNSName
// semantics). A suffix "example.com" permits exactly "example.com" and any
// proper subdomain "<label>.example.com"; it must NOT match "notexample.com" or
// "evil-example.com" the way a bare strings.HasSuffix would. This mirrors the
// crypto-layer dnsPermitted matcher (PKIGOV-005 / CORRECT-004).
func suffixAllowed(dns string, suffixes []string) bool {
	for _, suf := range suffixes {
		suf = strings.TrimPrefix(suf, ".")
		if suf == "" {
			continue
		}
		if dns == suf || strings.HasSuffix(dns, "."+suf) {
			return true
		}
	}
	return false
}

// Duration is a JSON-friendly time.Duration that (un)marshals as a Go duration
// string ("2160h"), so stored profiles are human-readable.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "0" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("profile: invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}
