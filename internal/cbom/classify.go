// SPDX-License-Identifier: BUSL-1.1

package cbom

import (
	"fmt"
	"strings"
)

// Strength rates a cryptographic observation.
type Strength string

const (
	StrengthStrong     Strength = "strong"     // modern
	StrengthAcceptable Strength = "acceptable" // sound today, but watch (e.g. quantum-vulnerable)
	StrengthWeak       Strength = "weak"       // undersized, deprecated, or banned
)

// Classification is the verdict on one observation.
type Classification struct {
	Strength          Strength `json:"strength"`
	QuantumVulnerable bool     `json:"quantum_vulnerable"`
	OutOfPolicy       bool     `json:"out_of_policy"`
	Reasons           []string `json:"reasons,omitempty"`
}

// Policy is the bar each observation is judged against.
type Policy struct {
	MinRSABits    int      // minimum acceptable RSA modulus
	MinECBits     int      // minimum acceptable elliptic-curve size
	MinTLSVersion string   // minimum acceptable TLS version, e.g. "TLSv1.2"
	BannedCiphers []string // substrings that mark a cipher weak (case-insensitive)
}

// DefaultPolicy is a sensible modern baseline.
func DefaultPolicy() Policy {
	return Policy{
		MinRSABits:    2048,
		MinECBits:     256,
		MinTLSVersion: "TLSv1.2",
		BannedCiphers: []string{"3DES", "DES", "RC4", "NULL", "EXPORT", "MD5", "ANON"},
	}
}

// TLS protocol-version codepoints (RFC 8446 et al.). Defined here, not imported
// from crypto/tls, so this package stays outside the crypto boundary.
const (
	versionSSL30 uint16 = 0x0300
	versionTLS10 uint16 = 0x0301
	versionTLS11 uint16 = 0x0302
	versionTLS12 uint16 = 0x0303
	versionTLS13 uint16 = 0x0304
)

// TLSVersionName maps a TLS version codepoint to its name.
func TLSVersionName(v uint16) string {
	switch v {
	case versionSSL30:
		return "SSLv3"
	case versionTLS10:
		return "TLSv1.0"
	case versionTLS11:
		return "TLSv1.1"
	case versionTLS12:
		return "TLSv1.2"
	case versionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// tlsRank orders TLS versions so a policy minimum can be compared.
var tlsRank = map[string]int{"SSLv3": 0, "TLSv1.0": 1, "TLSv1.1": 2, "TLSv1.2": 3, "TLSv1.3": 4}

// Classify dispatches on the crypto fact a finding carries.
func Classify(f Finding, p Policy) Classification {
	switch {
	case f.Protocol != "":
		return ClassifyProtocol(f.Protocol, p)
	case f.Cipher != "":
		return ClassifyCipher(f.Cipher, p)
	case f.Algorithm != "":
		return ClassifyKey(f.Algorithm, f.KeyBits, p)
	default:
		return Classification{Strength: StrengthAcceptable}
	}
}

// keyFamily normalizes an algorithm name to a family.
func keyFamily(algorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.HasPrefix(a, "RSA"):
		return "RSA"
	case strings.HasPrefix(a, "ECDSA") || strings.HasPrefix(a, "EC") || strings.Contains(a, "P-"):
		return "ECDSA"
	case strings.HasPrefix(a, "ED25519") || strings.HasPrefix(a, "ED448"):
		return "EdDSA"
	case strings.HasPrefix(a, "DSA"):
		return "DSA"
	default:
		return "unknown"
	}
}

// ClassifyKey classifies an asymmetric public key by family and size. RSA,
// ECDSA, EdDSA, and DSA are quantum-vulnerable. An installed licensed
// classifier is consulted first, so licensed algorithm families the core
// deliberately does not know classify correctly instead of falling into
// "unrecognized".
func ClassifyKey(algorithm string, bits int, p Policy) Classification {
	if licensedClassifyKey != nil {
		if c, ok := licensedClassifyKey(algorithm, bits); ok {
			return c
		}
	}
	fam := keyFamily(algorithm)
	c := Classification{Strength: StrengthAcceptable}
	switch fam {
	case "RSA", "DSA":
		c.QuantumVulnerable = true
		c.Reasons = append(c.Reasons, fam+" is breakable by a cryptographically-relevant quantum computer")
		if fam == "DSA" {
			c.Strength = StrengthWeak
			c.OutOfPolicy = true
			c.Reasons = append(c.Reasons, "DSA is deprecated")
		} else if bits > 0 && bits < p.MinRSABits {
			c.Strength = StrengthWeak
			c.OutOfPolicy = true
			c.Reasons = append(c.Reasons, fmt.Sprintf("RSA %d-bit is below the %d-bit minimum", bits, p.MinRSABits))
		}
	case "ECDSA", "EdDSA":
		c.QuantumVulnerable = true
		c.Reasons = append(c.Reasons, fam+" is breakable by a cryptographically-relevant quantum computer")
		if bits > 0 && bits < p.MinECBits {
			c.Strength = StrengthWeak
			c.OutOfPolicy = true
			c.Reasons = append(c.Reasons, fmt.Sprintf("%d-bit curve is below the %d-bit minimum", bits, p.MinECBits))
		}
	default:
		c.Reasons = append(c.Reasons, "unrecognized algorithm "+algorithm)
	}
	return c
}

// ClassifyProtocol classifies a TLS protocol version against the policy minimum.
func ClassifyProtocol(version string, p Policy) Classification {
	c := Classification{Strength: StrengthAcceptable}
	rank, ok := tlsRank[version]
	min := tlsRank[p.MinTLSVersion]
	switch {
	case ok && rank < min:
		c.Strength = StrengthWeak
		c.OutOfPolicy = true
		c.Reasons = append(c.Reasons, version+" is below the "+p.MinTLSVersion+" minimum")
	case ok && rank >= 4: // TLS 1.3
		c.Strength = StrengthStrong
	}
	return c
}

// ClassifyCipher classifies a cipher suite name: any banned substring marks it
// weak and out of policy.
func ClassifyCipher(name string, p Policy) Classification {
	c := Classification{Strength: StrengthAcceptable}
	up := strings.ToUpper(name)
	for _, banned := range p.BannedCiphers {
		if strings.Contains(up, strings.ToUpper(banned)) {
			c.Strength = StrengthWeak
			c.OutOfPolicy = true
			c.Reasons = append(c.Reasons, "cipher contains banned primitive "+banned)
			return c
		}
	}
	return c
}
