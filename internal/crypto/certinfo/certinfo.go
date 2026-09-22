// SPDX-License-Identifier: BUSL-1.1

// Package certinfo extracts inventory metadata from an X.509 certificate inside
// the AN-3 crypto boundary (a subpackage of internal/crypto, so it alone may
// import crypto/x509). Callers outside the boundary consume only the crypto-free
// Info struct, so the certificate-inventory layer never imports crypto/*.
package certinfo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- SHA-1 only for the conventional certificate fingerprint identifier, never integrity (CWE-328)
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Info is the inventory metadata of a certificate.
type Info struct {
	Subject           string
	CommonName        string // parsed subject CN, not inferred from the display string
	Issuer            string
	SerialNumber      string // hex
	DNSNames          []string
	IPAddresses       []string
	EmailAddresses    []string
	URIs              []string
	NotBefore         time.Time
	NotAfter          time.Time
	SHA256Fingerprint string // hex of the DER
	// SPKISHA256 is SHA-256 over canonical SubjectPublicKeyInfo DER. Unlike the
	// certificate fingerprint it stays stable across cross-signing, so callers
	// can correlate the same public CA key without comparing display names.
	SPKISHA256    string
	KeyAlgorithm  string
	PublicKeyBits int // key size in bits (RSA modulus, EC curve, 256 for Ed25519); 0 if unknown
	IsCA          bool
	ExtKeyUsages  []string // extended key usages, known names or dotted custom OIDs

	// RFC 5280 profile fields surfaced for served-leaf conformance checks
	// (PKIGOV-001). Empty/absent extensions yield empty slices.
	SubjectKeyID          string   // hex of the Subject Key Identifier
	AuthorityKeyID        string   // hex of the Authority Key Identifier
	CRLDistributionPoints []string // CDP URLs
	OCSPServers           []string // AIA OCSP responder URLs
	IssuingCertificateURL []string // AIA CA-issuers URLs
	PolicyOIDs            []string // certificatePolicies, dotted form

	// Structural profile fields for the RFC 5280 profile linter (PKIGOV-009), kept
	// inside the crypto boundary so the linter never imports crypto/x509.
	Version            int    // certificate version (3 for v3)
	SignatureAlgorithm string // e.g. "SHA256-RSA", "ECDSA-SHA256"
	KeyUsageSet        bool   // whether a keyUsage extension is present (non-zero)
	KeyUsageDigitalSig bool   // digitalSignature bit
	KeyUsageEncipher   bool   // keyEncipherment bit
	KeyUsageCertSign   bool   // keyCertSign bit
	BasicConstraints   bool   // whether basicConstraints is present/valid
}

// LeafDER returns a copy of the first certificate's canonical DER bytes from a
// DER value or PEM chain. Inventory/event producers use this boundary helper so
// crypto/x509 and encoding/pem never leak into business packages (AN-3).
func LeafDER(raw []byte) ([]byte, error) {
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("certinfo: PEM block is %q, not CERTIFICATE", block.Type)
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certinfo: parse certificate: %w", err)
	}
	return bytes.Clone(cert.Raw), nil
}

// Inspect parses a certificate (PEM or DER) and returns its inventory metadata.
func Inspect(raw []byte) (Info, error) {
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return Info{}, fmt.Errorf("certinfo: PEM block is %q, not CERTIFICATE", block.Type)
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Info{}, fmt.Errorf("certinfo: parse certificate: %w", err)
	}
	if cert.SerialNumber == nil {
		return Info{}, errors.New("certinfo: certificate has no serial number")
	}

	sum := sha256.Sum256(cert.Raw)
	spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	info := Info{
		Subject:           cert.Subject.String(),
		CommonName:        cert.Subject.CommonName,
		Issuer:            cert.Issuer.String(),
		SerialNumber:      cert.SerialNumber.Text(16),
		DNSNames:          cert.DNSNames,
		EmailAddresses:    cert.EmailAddresses,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		SHA256Fingerprint: hex.EncodeToString(sum[:]),
		SPKISHA256:        hex.EncodeToString(spkiSum[:]),
		KeyAlgorithm:      cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:     publicKeyBits(cert.PublicKey),
		IsCA:              cert.IsCA,
	}
	// Structural inventory only: neither certificate trust nor issuer signature.
	if cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		algorithm, err := inspectMLDSASubject(cert.RawSubjectPublicKeyInfo)
		if err != nil {
			return Info{}, err
		}
		if algorithm != "" {
			info.KeyAlgorithm = algorithm
		}
	}
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	for _, u := range cert.URIs {
		info.URIs = append(info.URIs, u.String())
	}
	// RFC 5280 profile fields (PKIGOV-001): the served-leaf conformance check reads
	// these to assert CDP/AIA/SKI/policies are present and well-formed.
	if len(cert.SubjectKeyId) > 0 {
		info.SubjectKeyID = hex.EncodeToString(cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		info.AuthorityKeyID = hex.EncodeToString(cert.AuthorityKeyId)
	}
	info.CRLDistributionPoints = append(info.CRLDistributionPoints, cert.CRLDistributionPoints...)
	info.OCSPServers = append(info.OCSPServers, cert.OCSPServer...)
	info.IssuingCertificateURL = append(info.IssuingCertificateURL, cert.IssuingCertificateURL...)
	info.PolicyOIDs = policyStrings(cert)
	info.ExtKeyUsages = extKeyUsageStrings(cert)
	// Structural fields for the RFC 5280 profile linter (PKIGOV-009).
	info.Version = cert.Version
	info.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	info.KeyUsageSet = cert.KeyUsage != 0
	info.KeyUsageDigitalSig = cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
	info.KeyUsageEncipher = cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0
	info.KeyUsageCertSign = cert.KeyUsage&x509.KeyUsageCertSign != 0
	info.BasicConstraints = cert.BasicConstraintsValid
	return info, nil
}

// VerifyHostname applies the standard X.509 DNS/IP name rules to a PEM or DER
// certificate. It stays inside the crypto boundary because VerifyHostname is a
// crypto/x509 operation; callers need only the pass/fail fact.
func VerifyHostname(raw []byte, hostname string) error {
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("certinfo: PEM block is %q, not CERTIFICATE", block.Type)
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("certinfo: parse certificate: %w", err)
	}
	return cert.VerifyHostname(strings.TrimSpace(hostname))
}

// InspectAll parses every certificate in raw. PEM bundles may contain private-key
// blocks next to certificate blocks; this helper ignores non-certificate PEM
// blocks and returns only public certificate metadata. Non-PEM input is tried as
// DER, then as base64-encoded DER. No secret value is returned.
func InspectAll(raw []byte) ([]Info, error) {
	// DER is binary: a signature byte can look like textual whitespace.
	// Parse the exact bytes before trimming PEM or base64 envelopes.
	if info, err := inspectDER(raw); err == nil {
		return []Info{info}, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	var out []Info
	rest := trimmed
	sawPEM := false
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		if block.Type == "CERTIFICATE" {
			info, err := inspectDER(block.Bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, info)
		}
		rest = next
	}
	if sawPEM {
		return out, nil
	}
	if info, err := inspectDER(trimmed); err == nil {
		return []Info{info}, nil
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err := base64.StdEncoding.Decode(decoded, trimmed)
	if err != nil {
		return nil, nil
	}
	decoded = decoded[:n]
	defer secret.Wipe(decoded)
	info, err := inspectDER(decoded)
	if err != nil {
		return nil, nil
	}
	return []Info{info}, nil
}

func inspectDER(der []byte) (Info, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Info{}, fmt.Errorf("certinfo: parse certificate: %w", err)
	}
	if cert.SerialNumber == nil {
		return Info{}, errors.New("certinfo: certificate has no serial number")
	}

	sum := sha256.Sum256(cert.Raw)
	spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	info := Info{
		Subject:           cert.Subject.String(),
		CommonName:        cert.Subject.CommonName,
		Issuer:            cert.Issuer.String(),
		SerialNumber:      cert.SerialNumber.Text(16),
		DNSNames:          cert.DNSNames,
		EmailAddresses:    cert.EmailAddresses,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		SHA256Fingerprint: hex.EncodeToString(sum[:]),
		SPKISHA256:        hex.EncodeToString(spkiSum[:]),
		KeyAlgorithm:      cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:     publicKeyBits(cert.PublicKey),
		IsCA:              cert.IsCA,
	}
	// Structural inventory only: neither certificate trust nor issuer signature.
	if cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		algorithm, err := inspectMLDSASubject(cert.RawSubjectPublicKeyInfo)
		if err != nil {
			return Info{}, err
		}
		if algorithm != "" {
			info.KeyAlgorithm = algorithm
		}
	}
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	for _, u := range cert.URIs {
		info.URIs = append(info.URIs, u.String())
	}
	if len(cert.SubjectKeyId) > 0 {
		info.SubjectKeyID = hex.EncodeToString(cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		info.AuthorityKeyID = hex.EncodeToString(cert.AuthorityKeyId)
	}
	info.CRLDistributionPoints = append(info.CRLDistributionPoints, cert.CRLDistributionPoints...)
	info.OCSPServers = append(info.OCSPServers, cert.OCSPServer...)
	info.IssuingCertificateURL = append(info.IssuingCertificateURL, cert.IssuingCertificateURL...)
	info.PolicyOIDs = policyStrings(cert)
	info.ExtKeyUsages = extKeyUsageStrings(cert)
	info.Version = cert.Version
	info.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	info.KeyUsageSet = cert.KeyUsage != 0
	info.KeyUsageDigitalSig = cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
	info.KeyUsageEncipher = cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0
	info.KeyUsageCertSign = cert.KeyUsage&x509.KeyUsageCertSign != 0
	info.BasicConstraints = cert.BasicConstraintsValid
	return info, nil
}

func extKeyUsageStrings(cert *x509.Certificate) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, usage := range cert.ExtKeyUsage {
		add(extKeyUsageString(usage))
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		add(oid.String())
	}
	return out
}

func extKeyUsageString(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "codeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "emailProtection"
	case x509.ExtKeyUsageTimeStamping:
		return "timeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "ocspSigning"
	default:
		if oid := ExtKeyUsageOID(usage); oid != nil {
			return oid.String()
		}
		return ""
	}
}

// ExtKeyUsageOID returns the dotted-form OID for a Go-known extended key
// usage that has no conventional short name, or nil for usages outside this
// table. internal/crypto's hierarchy EKU renderer shares it (AUD-201 follow-up
// E1/V13) so the emitting and inspecting sides cannot drift into two naming
// schemes again.
func ExtKeyUsageOID(usage x509.ExtKeyUsage) asn1.ObjectIdentifier {
	switch usage {
	case x509.ExtKeyUsageIPSECEndSystem:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	case x509.ExtKeyUsageIPSECTunnel:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	case x509.ExtKeyUsageIPSECUser:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
	default:
		return nil
	}
}

// policyStrings returns the certificatePolicies OIDs in dotted form, reading the
// Go 1.22+ parsed cert.Policies ([]x509.OID) and falling back to the deprecated
// cert.PolicyIdentifiers, de-duplicated. (x509.CreateCertificate writes the
// extension from either field; ParseCertificate populates Policies, and only
// populates PolicyIdentifiers for OIDs representable as asn1.ObjectIdentifier.)
func policyStrings(cert *x509.Certificate) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, oid := range cert.Policies {
		add(oid.String())
	}
	for _, oid := range cert.PolicyIdentifiers {
		add(oid.String())
	}
	return out
}

// publicKeyBits returns the key size in bits: the RSA modulus length, the EC
// curve size, 256 for Ed25519, or 0 for an unrecognized key. It is the signal
// the crypto-inventory (F52) uses to flag undersized keys.
func publicKeyBits(pub any) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// Thumbprint returns the certificate's Windows thumbprint: the uppercase
// hex-encoded SHA-1 digest of the certificate's DER encoding — the value the
// Windows certificate store and `netsh http ... certhash=` use to identify a
// certificate. SHA-1 is used here as an identifier, not a signature.
func Thumbprint(raw []byte) (string, error) {
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("certinfo: PEM block is %q, not CERTIFICATE", block.Type)
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("certinfo: parse certificate: %w", err)
	}
	sum := sha1.Sum(cert.Raw) // #nosec G401 -- display/lookup fingerprint in the industry-standard form; not a security control (CWE-328)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// PublicKeyJWKThumbprint returns the RFC 7638 JWK thumbprint (base64url SHA-256) of
// the certificate's public key, in the SAME canonical form the ACME account-key
// thumbprint uses (jose.ACMEKey.Thumbprint). It lets the ACME revokeCert handler
// authorize a revocation by the *certificate key* (RFC 8555 §7.6): the JWS's
// embedded JWK is authorized iff its thumbprint equals this value. Supports the same
// key families as ACME account keys (RSA, EC P-256/384/521, Ed25519); anything else
// is an error. crypto/* stays inside this boundary (AN-3).
func PublicKeyJWKThumbprint(raw []byte) (string, error) {
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("certinfo: PEM block is %q, not CERTIFICATE", block.Type)
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("certinfo: parse certificate: %w", err)
	}
	canonical, err := canonicalJWK(cert.PublicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// canonicalJWK renders the RFC 7638 canonical JWK JSON (required members only,
// lexicographic order, no whitespace) for an RSA/ECDSA/Ed25519 public key.
func canonicalJWK(pub any) (string, error) {
	enc := base64.RawURLEncoding.EncodeToString
	switch k := pub.(type) {
	case *rsa.PublicKey:
		eb := big.NewInt(int64(k.E)).Bytes()
		// RFC 7638 §3.2: RSA required members are e, kty, n.
		return fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, enc(eb), enc(k.N.Bytes())), nil
	case *ecdsa.PublicKey:
		crv, err := ecCurveName(k)
		if err != nil {
			return "", err
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		// RFC 7638 §3.2: EC required members are crv, kty, x, y, with fixed-width
		// coordinates (RFC 7518 §6.2.1.2).
		//nolint:staticcheck // JWK thumbprints are defined over legacy ECDSA affine coordinates.
		return fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`,
			crv, enc(leftPad(k.X.Bytes(), size)), enc(leftPad(k.Y.Bytes(), size))), nil
	case ed25519.PublicKey:
		// RFC 8037 §2: OKP thumbprint required members are crv, kty, x.
		return fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, enc(k)), nil
	default:
		return "", fmt.Errorf("certinfo: unsupported public key type %T for JWK thumbprint", pub)
	}
}

func ecCurveName(k *ecdsa.PublicKey) (string, error) {
	switch k.Curve {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	default:
		return "", fmt.Errorf("certinfo: unsupported EC curve %v", k.Curve.Params().Name)
	}
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
