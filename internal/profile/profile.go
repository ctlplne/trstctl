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
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
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
	AllowedIPCIDRs       []string     `json:"allowed_ip_cidrs"`            // IP SAN ranges; set to permit IP SANs under a SAN policy
	AllowedEmailDomains  []string     `json:"allowed_email_domains"`       // rfc822Name domains; set to permit email SANs under a SAN policy
	AllowedURIPrefixes   []string     `json:"allowed_uri_prefixes"`        // URI string prefixes; set to permit URI SANs under a SAN policy
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

// ValidateSpec checks a serialized certificate profile before it is committed to
// the event log. Served profile selection must reject unknown algorithm labels
// here, before an unsupported policy can be listed or selected later.
func ValidateSpec(spec json.RawMessage) error {
	var p CertificateProfile
	if err := json.Unmarshal(spec, &p); err != nil {
		return fmt.Errorf("profile: decode certificate profile: %w", err)
	}
	return p.ValidateDefinition()
}

// ValidateDefinition checks profile authoring-time constraints. Validate checks a
// concrete issuance request against an already-authored profile.
func (p CertificateProfile) ValidateDefinition() error {
	id := fmt.Sprintf("profile %q v%d", p.Name, p.Version)
	if _, err := NormalizeACMEAuthMode(p.ACMEAuthMode); err != nil {
		return fmt.Errorf("%s: %w", id, err)
	}
	for _, label := range p.AllowedKeyAlgorithms {
		classification, err := crypto.ClassifyAlgorithmLabel(label)
		if err != nil {
			return fmt.Errorf("%s allowed_key_algorithms: %w", id, err)
		}
		if classification.Kind != "signature" {
			return fmt.Errorf("%s allowed_key_algorithms: %q is a %s primitive, not a certificate signing algorithm", id, label, classification.Kind)
		}
	}
	return nil
}

// Request is the backend-agnostic view of an issuance request to validate.
type Request struct {
	KeyAlgorithm   string        // from internal/crypto.CSRInfo
	KeyBits        int           // from internal/crypto.CSRInfo
	RequestedEKUs  []string      // EKUs the caller asks for
	TTL            time.Duration // requested validity
	DNSNames       []string      // SANs
	IPAddresses    []string      // SAN iPAddresses
	EmailAddresses []string      // SAN rfc822Names
	URIs           []string      // SAN uniformResourceIdentifiers
	Protocol       string        // "api" | "acme" | "est" | "scep" | "cmp" | ...
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
	sanPolicy := p.hasSANPolicy()
	if len(p.AllowedIPCIDRs) > 0 {
		if _, err := parseCIDRSet(p.AllowedIPCIDRs); err != nil {
			return fmt.Errorf("%s has invalid allowed IP CIDR policy: %w", id, err)
		}
	}
	for _, dns := range r.DNSNames {
		if len(p.AllowedDNSSuffixes) == 0 {
			if sanPolicy {
				return fmt.Errorf("%s does not permit DNS SAN %q (no allowed DNS suffixes configured)", id, dns)
			}
			continue
		}
		if !suffixAllowed(dns, p.AllowedDNSSuffixes) {
			return fmt.Errorf("%s does not permit DNS SAN %q (allowed suffixes: %s)", id, dns, strings.Join(p.AllowedDNSSuffixes, ", "))
		}
	}
	for _, ip := range r.IPAddresses {
		if len(p.AllowedIPCIDRs) == 0 {
			if sanPolicy {
				return fmt.Errorf("%s does not permit IP SAN %q (no allowed IP CIDRs configured)", id, ip)
			}
			continue
		}
		if ok, err := ipAllowed(ip, p.AllowedIPCIDRs); err != nil {
			return fmt.Errorf("%s cannot evaluate IP SAN %q: %w", id, ip, err)
		} else if !ok {
			return fmt.Errorf("%s does not permit IP SAN %q (allowed CIDRs: %s)", id, ip, strings.Join(p.AllowedIPCIDRs, ", "))
		}
	}
	for _, email := range r.EmailAddresses {
		if len(p.AllowedEmailDomains) == 0 {
			if sanPolicy {
				return fmt.Errorf("%s does not permit email SAN %q (no allowed email domains configured)", id, email)
			}
			continue
		}
		if !emailAllowed(email, p.AllowedEmailDomains) {
			return fmt.Errorf("%s does not permit email SAN %q (allowed domains: %s)", id, email, strings.Join(p.AllowedEmailDomains, ", "))
		}
	}
	for _, uri := range r.URIs {
		if len(p.AllowedURIPrefixes) == 0 {
			if sanPolicy {
				return fmt.Errorf("%s does not permit URI SAN %q (no allowed URI prefixes configured)", id, uri)
			}
			continue
		}
		if !uriPrefixAllowed(uri, p.AllowedURIPrefixes) {
			return fmt.Errorf("%s does not permit URI SAN %q (allowed prefixes: %s)", id, uri, strings.Join(p.AllowedURIPrefixes, ", "))
		}
	}
	return nil
}

func (p CertificateProfile) hasSANPolicy() bool {
	return len(p.AllowedDNSSuffixes)+len(p.AllowedIPCIDRs)+len(p.AllowedEmailDomains)+len(p.AllowedURIPrefixes) > 0
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
	dns = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(dns)), ".")
	for _, suf := range suffixes {
		suf = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(strings.TrimPrefix(suf, "."))), ".")
		if suf == "" {
			continue
		}
		if dns == suf || strings.HasSuffix(dns, "."+suf) {
			return true
		}
	}
	return false
}

func ipAllowed(raw string, cidrs []string) (bool, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false, fmt.Errorf("invalid IP address: %w", err)
	}
	prefixes, err := parseCIDRSet(cidrs)
	if err != nil {
		return false, err
	}
	for _, pfx := range prefixes {
		if pfx.Contains(addr) {
			return true, nil
		}
	}
	return false, nil
}

func parseCIDRSet(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, raw := range cidrs {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR prefix: %w", raw, err)
		}
		out = append(out, pfx)
	}
	return out, nil
}

func emailAllowed(email string, domains []string) bool {
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return false
	}
	return suffixAllowed(email[at+1:], domains)
}

func uriPrefixAllowed(uri string, prefixes []string) bool {
	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" && strings.HasPrefix(uri, prefix) {
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
