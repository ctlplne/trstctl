// Package profilelint is a structural RFC 5280 / CA-Browser-Forum profile linter for
// issued certificates (PKIGOV-009). It is the in-tree stand-in for an external
// public-CA linter (zlint / certlint): those tools are not vendored, so this package
// encodes the high-value structural checks they perform — version, serial bounds,
// validity ordering and length, BasicConstraints, key usage, SAN presence, SKI/AKI
// presence, signature-algorithm sanity, and minimum key strength — as code the
// issuance test suite runs over a sample of every issued profile. It FAILS (returns
// error-level findings) on a malformed profile, so a profile regression (a missing
// extension, a missing SAN, an over-long validity) is caught in CI.
//
// It reads the certificate only through the crypto boundary's certinfo.Inspect
// (AN-3): this package imports no crypto/* itself. This is a structural lint, not
// the full zlint corpus; wiring an external public-CA linter as a CI gate is tracked
// as EXC-GATE-01 (see docs/limitations.md). The checks are deliberately conservative
// so they never false-positive on a conformant trstctl-issued leaf.
package profilelint

import (
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Severity classifies a finding. Error-level findings fail the lint; Warning-level
// findings are advisory, mirroring zlint's error/warn split.
type Severity int

const (
	// Warning is advisory: a deviation from best practice that is not a hard
	// RFC 5280 violation.
	Warning Severity = iota
	// Error is a hard profile violation that fails the lint.
	Error
)

func (s Severity) String() string {
	if s == Error {
		return "error"
	}
	return "warning"
}

// Finding is one lint result.
type Finding struct {
	Severity Severity
	Code     string // short stable id, e.g. "e_serial_too_long"
	Message  string
}

// Options tunes the lint for the certificate's role.
type Options struct {
	// Leaf asserts the certificate is an end-entity (not a CA): SAN required, IsCA
	// must be false, and a leaf-appropriate key usage is expected.
	Leaf bool
	// MaxValidity caps the certificate validity span. Zero disables the check.
	MaxValidity time.Duration
}

// maxSerialHexLen is twice the RFC 5280 §4.1.2.2 20-octet serial limit, since
// certinfo reports the serial as a lowercase hex string (2 hex chars per octet).
const maxSerialHexLen = 40

// weakSignatureAlgorithms are the SHA-1/MD-family signature algorithms an external
// linter flags. Compared case-insensitively against certinfo's algorithm string
// (e.g. "SHA1-RSA", "ECDSA-SHA1", "MD5-RSA").
var weakSignatureAlgorithms = []string{"md2", "md5", "sha1"}

// Lint inspects raw (PEM or DER) via the crypto boundary and runs the structural
// RFC 5280 profile checks, returning all findings. A nil/empty findings slice means
// the certificate passed; HasErrors reports whether any finding is fatal.
func Lint(raw []byte, opts Options) ([]Finding, error) {
	info, err := certinfo.Inspect(raw)
	if err != nil {
		return nil, fmt.Errorf("profilelint: %w", err)
	}

	var fs []Finding
	add := func(sev Severity, code, msg string) { fs = append(fs, Finding{sev, code, msg}) }

	// Version: RFC 5280 requires v3 (reported as 3) whenever extensions are present —
	// which a conformant profile always has.
	if info.Version != 0 && info.Version != 3 {
		add(Error, "e_cert_not_v3", fmt.Sprintf("certificate version is %d, want 3 (v3)", info.Version))
	}

	// Serial: a positive, non-zero integer of at most 20 octets (§4.1.2.2). certinfo
	// reports it as lowercase hex with no sign; an empty or "0" serial is invalid.
	switch {
	case info.SerialNumber == "" || info.SerialNumber == "0":
		add(Error, "e_serial_not_positive", "serial number must be a positive integer")
	case len(strings.TrimPrefix(info.SerialNumber, "-")) > maxSerialHexLen:
		add(Error, "e_serial_too_long", fmt.Sprintf("serial number is %d hex chars (>20 octets)", len(info.SerialNumber)))
	}

	// Validity ordering and presence (§4.1.2.5).
	if info.NotBefore.IsZero() || info.NotAfter.IsZero() {
		add(Error, "e_validity_missing", "notBefore/notAfter must be set")
	} else if !info.NotBefore.Before(info.NotAfter) {
		add(Error, "e_validity_not_ordered", "notBefore must be strictly before notAfter")
	}
	if opts.MaxValidity > 0 && !info.NotBefore.IsZero() && !info.NotAfter.IsZero() {
		if span := info.NotAfter.Sub(info.NotBefore); span > opts.MaxValidity {
			add(Error, "e_validity_too_long", fmt.Sprintf("validity span %s exceeds the profile cap %s", span, opts.MaxValidity))
		}
	}

	// BasicConstraints presence; a leaf must not be a CA.
	if !info.BasicConstraints {
		add(Error, "e_basic_constraints_absent", "basicConstraints extension is absent")
	}
	if opts.Leaf && info.IsCA {
		add(Error, "e_leaf_is_ca", "an end-entity certificate must not assert CA=true")
	}

	// Key usage: must be present; a CA needs keyCertSign.
	if !info.KeyUsageSet {
		add(Error, "e_key_usage_absent", "keyUsage extension is absent or empty")
	} else if info.IsCA && !info.KeyUsageCertSign {
		add(Error, "e_ca_without_cert_sign", "a CA certificate must assert keyCertSign")
	}

	// SAN: a leaf MUST carry a subjectAltName (§4.2.1.6).
	if opts.Leaf {
		if len(info.DNSNames)+len(info.IPAddresses)+len(info.EmailAddresses)+len(info.URIs) == 0 {
			add(Error, "e_leaf_without_san", "an end-entity certificate must carry a subjectAltName")
		}
	}

	// SubjectKeyIdentifier presence (§4.2.1.2).
	if info.SubjectKeyID == "" {
		add(Error, "e_ski_absent", "subjectKeyIdentifier extension is absent")
	}
	// AuthorityKeyIdentifier: required on a non-self-signed certificate (§4.2.1.1).
	selfSigned := info.Subject == info.Issuer
	if !selfSigned && info.AuthorityKeyID == "" {
		add(Error, "e_aki_absent", "authorityKeyIdentifier extension is absent on a non-self-signed certificate")
	}

	// Signature algorithm: reject the known-broken SHA-1/MD families.
	algLower := strings.ToLower(info.SignatureAlgorithm)
	for _, weak := range weakSignatureAlgorithms {
		if strings.Contains(algLower, weak) {
			add(Error, "e_weak_signature_algorithm", fmt.Sprintf("weak signature algorithm %s", info.SignatureAlgorithm))
			break
		}
	}

	// Public-key strength: RSA below 2048 bits is under the CA/B floor. certinfo
	// reports PublicKeyBits as the RSA modulus length / EC curve size; EC and Ed25519
	// keys (>=256) are acceptable, so only flag a small RSA modulus.
	if strings.Contains(strings.ToUpper(info.KeyAlgorithm), "RSA") && info.PublicKeyBits > 0 && info.PublicKeyBits < 2048 {
		add(Error, "e_rsa_modulus_too_small", fmt.Sprintf("RSA modulus is %d bits, below the 2048-bit floor", info.PublicKeyBits))
	}

	return fs, nil
}

// HasErrors reports whether any finding is Error-level (i.e. the lint fails).
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == Error {
			return true
		}
	}
	return false
}

// Errors returns only the Error-level findings, for a concise failure message.
func Errors(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Severity == Error {
			out = append(out, f)
		}
	}
	return out
}
