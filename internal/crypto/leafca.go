package crypto

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SelfSignedCACert creates a self-signed CA certificate whose signing key is the
// given DigestSigner. In production that signer is a key held inside the
// out-of-process signing service (AN-4): the raw private key never leaves the
// signer; only digests cross the boundary. The certificate is returned as DER.
func SelfSignedCACert(signer DigestSigner, commonName string, ttl time.Duration) ([]byte, error) {
	adapter, err := newX509Signer(signer)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, adapter.Public(), adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: self-sign CA: %w", err)
	}
	return der, nil
}

// LeafProfile carries the served issuing CA's RFC 5280 / CA-Browser-Forum profile
// for an end-entity certificate: the revocation pointers a relying party needs to
// check status, the issuer-certificate pointer for chain building, the policy OIDs
// the certificate is issued under, and the constraints the issuance must satisfy.
// It lives inside the crypto boundary (AN-3) so the issuance code never names
// crypto/x509. The zero value adds no extension and enforces no constraint —
// SignLeafFromCSR uses it, preserving the legacy leaf shape for callers that have
// no served revocation infrastructure (test/library CAs, breakglass, the protocol
// servers' own CAs).
type LeafProfile struct {
	// Revocation + chain-building pointers (PKIGOV-001). Empty slices omit the
	// corresponding extension.
	CRLDistributionPoints []string // CDP URLs (CRL location)
	OCSPServers           []string // AIA OCSP responder URLs
	IssuingCertificateURL []string // AIA CA-issuers URLs (parent cert location)

	// CertificatePolicyOIDs are dotted OIDs placed in the certificatePolicies
	// extension (e.g. "2.23.140.1.2.1" for the CA/B domain-validated policy). Empty
	// omits the extension.
	CertificatePolicyOIDs []string

	// ExtraExtensions are non-core X.509 extensions already DER-encoded by another
	// crypto-boundary helper. They are covered by the certificate signature.
	ExtraExtensions []CertificateExtension

	// Constraints enforced before signing (PKIGOV-002). A request that exceeds them
	// is rejected with ErrLeafProfileViolation rather than signed. A completely
	// empty SAN policy keeps the legacy signer unconstrained; once any SAN policy is
	// present, each requested SAN type needs its own explicit allow-list.
	MaxValidity           time.Duration // validity ceiling; 0 = no ceiling
	AllowedKeyUsages      *KeyUsages    // when set, the leaf's key usages; nil keeps the default
	AllowedExtKeyUsage    []string      // EKU allow-list ("serverAuth","clientAuth",...); empty = default pair
	PermittedDNSSuffixes  []string      // DNS SAN suffixes; set to permit DNS SANs under a SAN policy
	PermittedIPCIDRs      []string      // IP SAN CIDR ranges; set to permit IP SANs under a SAN policy
	PermittedEmailDomains []string      // email SAN domains; set to permit rfc822Name SANs under a SAN policy
	PermittedURIPrefixes  []string      // URI SAN prefixes; set to permit URI SANs under a SAN policy
}

// KeyUsages is the backend-agnostic set of X.509 key-usage bits a leaf may carry,
// so a profile can pin them without the caller importing crypto/x509 (AN-3).
type KeyUsages struct {
	DigitalSignature bool
	KeyEncipherment  bool
	KeyAgreement     bool
	DataEncipherment bool
}

// ErrLeafProfileViolation is returned when a CSR/TTL violates the bound
// LeafProfile (PKIGOV-002): the request is rejected before any signature, so an
// out-of-profile certificate is never minted.
type leafProfileError struct{ msg string }

func (e *leafProfileError) Error() string { return "crypto: leaf profile violation: " + e.msg }

// IsLeafProfileViolation reports whether err is a leaf-profile rejection, letting
// the served issuance path map it to a profile-deny decision without importing
// crypto internals.
func IsLeafProfileViolation(err error) bool {
	var le *leafProfileError
	return asErr(err, &le)
}

// SignLeafFromCSR validates a CSR and signs an end-entity certificate with the CA
// key (a DigestSigner). It then VERIFIES the issued certificate against the CA
// before returning it: a signer that returns a signature which does not verify
// causes issuance to fail closed rather than emit an unverifiable certificate.
//
// It always sets the leaf's Subject Key Identifier (derived from the subject
// public key, RFC 5280 §4.2.1.2 method 1) so the certificate is chain-buildable;
// the Authority Key Identifier is filled from the issuing CA automatically. It
// adds no revocation pointers or policies — callers that serve revocation use
// SignLeafFromCSRWithProfile with a populated LeafProfile (PKIGOV-001).
func SignLeafFromCSR(caCertDER []byte, caSigner DigestSigner, csrDER []byte, ttl time.Duration) ([]byte, error) {
	return SignLeafFromCSRWithProfile(caCertDER, caSigner, csrDER, ttl, LeafProfile{})
}

// SignLeafFromCSRWithProfile is SignLeafFromCSR with an explicit issuing profile
// (PKIGOV-001/002). Before signing it enforces the profile's constraints — the
// validity ceiling, the EKU allow-list, and the DNS/IP/email/URI SAN constraints
// — and rejects an out-of-profile request with a leafProfileError (see
// IsLeafProfileViolation). On the issued certificate it stamps the Subject Key
// Identifier; all permitted SANs from the CSR; and, from the profile, the CRL
// distribution points, the AIA OCSP and CA-issuers URLs, the certificatePolicies,
// and the configured key usages — the RFC 5280 / BR fields the served leaf
// previously omitted. The issued certificate is verified against the CA before
// return (fail closed).
func SignLeafFromCSRWithProfile(caCertDER []byte, caSigner DigestSigner, csrDER []byte, ttl time.Duration, prof LeafProfile) ([]byte, error) {
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CA cert: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("crypto: CSR signature: %w", err)
	}
	// Enforce the profile's constraints before signing (PKIGOV-002): an
	// out-of-profile request is rejected, never minted.
	if err := enforceLeafProfile(csr, ttl, prof); err != nil {
		return nil, err
	}
	adapter, err := newX509Signer(caSigner)
	if err != nil {
		return nil, err
	}
	knownEKUs, customEKUs, err := leafExtKeyUsage(prof.AllowedExtKeyUsage)
	if err != nil {
		return nil, &leafProfileError{err.Error()}
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	// Subject Key Identifier from the subject public key (RFC 5280 method 1) so the
	// leaf is chain-buildable even when the CA cert lacks one to copy.
	ski, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              leafKeyUsageForProfile(prof),
		ExtKeyUsage:           knownEKUs,
		UnknownExtKeyUsage:    customEKUs,
		BasicConstraintsValid: true,
		SubjectKeyId:          ski,
		// Revocation + chain-building pointers (PKIGOV-001).
		CRLDistributionPoints: prof.CRLDistributionPoints,
		OCSPServer:            prof.OCSPServers,
		IssuingCertificateURL: prof.IssuingCertificateURL,
	}
	if len(prof.ExtraExtensions) > 0 {
		extra, err := x509Extensions(prof.ExtraExtensions)
		if err != nil {
			return nil, err
		}
		leaf.ExtraExtensions = append(leaf.ExtraExtensions, extra...)
	}
	// Authority Key Identifier from the issuing CA's SKI (when it has one) so the
	// AKI is present and correct even though we set the leaf SKI ourselves.
	if len(caCert.SubjectKeyId) > 0 {
		leaf.AuthorityKeyId = caCert.SubjectKeyId
	}
	if len(prof.CertificatePolicyOIDs) > 0 {
		// Set both the deprecated PolicyIdentifiers (asn1.ObjectIdentifier) and the
		// Go 1.22+ Policies ([]x509.OID); CreateCertificate writes the
		// certificatePolicies extension from either, and setting both keeps the
		// extension present across Go versions.
		pols, err := policyOIDs(prof.CertificatePolicyOIDs)
		if err != nil {
			return nil, err
		}
		leaf.PolicyIdentifiers = pols
		modern, err := modernPolicyOIDs(prof.CertificatePolicyOIDs)
		if err != nil {
			return nil, err
		}
		leaf.Policies = modern
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, csr.PublicKey, adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign leaf: %w", err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse issued leaf: %w", err)
	}
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		return nil, fmt.Errorf("crypto: issued leaf failed verification (signer misbehaved): %w", err)
	}
	return der, nil
}

// SignTimestampingCertFromCSR signs a TSA end-entity certificate from a CSR. The
// leaf has the exact RFC 3161 purpose OpenSSL expects: digitalSignature key usage
// and a CRITICAL extendedKeyUsage containing only id-kp-timeStamping. Keeping this
// constructor inside internal/crypto preserves AN-3 while giving the served TSA a
// stock-client-verifiable certificate.
func SignTimestampingCertFromCSR(caCertDER []byte, caSigner DigestSigner, csrDER []byte, ttl time.Duration) ([]byte, error) {
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CA cert: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse TSA CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("crypto: TSA CSR signature: %w", err)
	}
	adapter, err := newX509Signer(caSigner)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	eku, err := marshalExtKeyUsageExtension([]string{"timeStamping"})
	if err != nil {
		return nil, err
	}
	eku.Critical = true
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          ski,
		ExtraExtensions:       []pkix.Extension{eku},
	}
	if len(caCert.SubjectKeyId) > 0 {
		leaf.AuthorityKeyId = caCert.SubjectKeyId
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, csr.PublicKey, adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign TSA cert: %w", err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse issued TSA cert: %w", err)
	}
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		return nil, fmt.Errorf("crypto: issued TSA cert failed verification (signer misbehaved): %w", err)
	}
	return der, nil
}

// SignServerCertFromCSR signs a PKCS#10 CSR as a TLS SERVER certificate
// (ExtKeyUsageServerAuth) with the CA key behind a DigestSigner — in production a
// CA key held inside the out-of-process signer (AN-4). It covers the given DNS/IP
// SANs (hosts that parse as IPs become IPAddresses, the rest dNSNames). It is how
// the control plane mints its OWN agent-channel server certificate from the
// signer-held agent CA: the agent (which pins/trusts the agent CA) then verifies the
// channel, while the agent CA private key never enters the control plane. The issued
// certificate is verified against the CA before return (fail closed). The chain is
// leaf || CA (DER list), PEM-encoded.
func SignServerCertFromCSR(caCertDER []byte, caSigner DigestSigner, csrDER []byte, hosts []string, ttl time.Duration) ([]byte, error) {
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CA cert: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse server CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("crypto: server CSR signature: %w", err)
	}
	adapter, err := newX509Signer(caSigner)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	var dnsNames []string
	var ipAddrs []net.IP
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          ski,
	}
	if len(caCert.SubjectKeyId) > 0 {
		leaf.AuthorityKeyId = caCert.SubjectKeyId
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, csr.PublicKey, adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign server cert: %w", err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse issued server cert: %w", err)
	}
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		return nil, fmt.Errorf("crypto: issued server cert failed verification (signer misbehaved): %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})...)
	return out, nil
}

// SignAgentClientCSR signs a PKCS#10 CSR as a short-lived agent mTLS CLIENT
// certificate (ExtKeyUsageClientAuth) with the CA key behind a DigestSigner —
// in production the agent CA key held inside the out-of-process signer (AN-4),
// so the raw CA private key never enters the control plane. It stamps the
// authorizing tenant into the certificate as the given SPIFFE URI SAN
// (spiffe://trstctl.example/tenant/<id>/agent/<cn>, built by the caller from the
// REDEEMED/PRESENTED tenant — never the CSR), so the mTLS consumer derives the
// tenant from the certificate, not a client-chosen field (WIRE-003/AN-1). It is
// the served agent-channel analogue of mtls.SignClientCSRWithTenant, which signs
// with an in-process CA key; this routes through the signer instead.
//
// The common name still comes from the CSR subject (the agent identity), but the
// tenant SPIFFE SAN does not. The issued certificate is VERIFIED against the CA
// before return, so a signer that returns a non-verifying signature fails closed
// rather than yielding an unusable client cert. The returned chain is leaf || CA
// (DER list), suitable for the agent to adopt directly.
func SignAgentClientCSR(caCertDER []byte, caSigner DigestSigner, csrDER []byte, spiffeURI string, ttl time.Duration) ([]byte, error) {
	if strings.TrimSpace(spiffeURI) == "" {
		return nil, errors.New("crypto: refusing to sign agent client CSR without a tenant SPIFFE SAN")
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse agent CA cert: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse agent CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("crypto: agent CSR signature: %w", err)
	}
	uri, err := url.Parse(spiffeURI)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse agent tenant SPIFFE SAN: %w", err)
	}
	adapter, err := newX509Signer(caSigner)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		URIs:                  []*url.URL{uri},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          ski,
	}
	if len(caCert.SubjectKeyId) > 0 {
		leaf.AuthorityKeyId = caCert.SubjectKeyId
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, csr.PublicKey, adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign agent client cert: %w", err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse issued agent cert: %w", err)
	}
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		return nil, fmt.Errorf("crypto: issued agent cert failed verification (signer misbehaved): %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})...)
	return out, nil
}

// enforceLeafProfile rejects a request that exceeds the profile's constraints
// (PKIGOV-002). It is conservative: a completely empty SAN policy leaves SANs
// unconstrained for legacy callers, but once one SAN allow-list is present, every
// requested SAN type must have its own matching allow-list.
func enforceLeafProfile(csr *x509.CertificateRequest, ttl time.Duration, prof LeafProfile) error {
	if prof.MaxValidity > 0 && ttl > prof.MaxValidity {
		return &leafProfileError{fmt.Sprintf("validity %s exceeds the profile ceiling %s", ttl, prof.MaxValidity)}
	}
	sanPolicy := leafSANPolicyConfigured(prof)
	cidrs, err := parseLeafCIDRs(prof.PermittedIPCIDRs)
	if err != nil {
		return &leafProfileError{fmt.Sprintf("invalid permitted IP CIDR policy: %v", err)}
	}
	for _, name := range csr.DNSNames {
		if len(prof.PermittedDNSSuffixes) == 0 {
			if sanPolicy {
				return &leafProfileError{fmt.Sprintf("DNS SAN %q is not permitted by this profile", name)}
			}
			continue
		}
		if !dnsSuffixPermitted(name, prof.PermittedDNSSuffixes) {
			return &leafProfileError{fmt.Sprintf("DNS SAN %q is outside the permitted DNS suffixes %v", name, prof.PermittedDNSSuffixes)}
		}
	}
	for _, ip := range csr.IPAddresses {
		if len(prof.PermittedIPCIDRs) == 0 {
			if sanPolicy {
				return &leafProfileError{fmt.Sprintf("IP SAN %q is not permitted by this profile", ip.String())}
			}
			continue
		}
		if !ipInCIDRs(ip, cidrs) {
			return &leafProfileError{fmt.Sprintf("IP SAN %q is outside the permitted CIDRs %v", ip.String(), prof.PermittedIPCIDRs)}
		}
	}
	for _, email := range csr.EmailAddresses {
		if len(prof.PermittedEmailDomains) == 0 {
			if sanPolicy {
				return &leafProfileError{fmt.Sprintf("email SAN %q is not permitted by this profile", email)}
			}
			continue
		}
		if !emailDomainPermitted(email, prof.PermittedEmailDomains) {
			return &leafProfileError{fmt.Sprintf("email SAN %q is outside the permitted email domains %v", email, prof.PermittedEmailDomains)}
		}
	}
	for _, uri := range csr.URIs {
		raw := uri.String()
		if len(prof.PermittedURIPrefixes) == 0 {
			if sanPolicy {
				return &leafProfileError{fmt.Sprintf("URI SAN %q is not permitted by this profile", raw)}
			}
			continue
		}
		if !uriPrefixPermitted(raw, prof.PermittedURIPrefixes) {
			return &leafProfileError{fmt.Sprintf("URI SAN %q is outside the permitted URI prefixes %v", raw, prof.PermittedURIPrefixes)}
		}
	}
	return nil
}

// subjectKeyID computes the RFC 5280 §4.2.1.2 method-1 key identifier: the SHA-1
// of the DER BIT STRING contents of the subject public key.
func subjectKeyID(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal public key for SKI: %w", err)
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("crypto: parse SPKI for SKI: %w", err)
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:], nil
}

// leafKeyUsage maps the profile's key usages to the x509 bitmask, defaulting to
// digitalSignature+keyEncipherment (the prior served-leaf usage) when unset.
func leafKeyUsage(u *KeyUsages) x509.KeyUsage {
	if u == nil {
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	var ku x509.KeyUsage
	if u.DigitalSignature {
		ku |= x509.KeyUsageDigitalSignature
	}
	if u.KeyEncipherment {
		ku |= x509.KeyUsageKeyEncipherment
	}
	if u.KeyAgreement {
		ku |= x509.KeyUsageKeyAgreement
	}
	if u.DataEncipherment {
		ku |= x509.KeyUsageDataEncipherment
	}
	if ku == 0 { // never emit an empty key-usage extension
		ku = x509.KeyUsageDigitalSignature
	}
	return ku
}

func x509Extensions(exts []CertificateExtension) ([]pkix.Extension, error) {
	out := make([]pkix.Extension, 0, len(exts))
	for _, ext := range exts {
		oid, err := parseOID(ext.OID)
		if err != nil {
			return nil, fmt.Errorf("crypto: extension OID %q: %w", ext.OID, err)
		}
		out = append(out, pkix.Extension{
			Id:       oid,
			Critical: ext.Critical,
			Value:    append([]byte(nil), ext.Value...),
		})
	}
	return out, nil
}

func leafKeyUsageForProfile(prof LeafProfile) x509.KeyUsage {
	if prof.AllowedKeyUsages != nil {
		return leafKeyUsage(prof.AllowedKeyUsages)
	}
	if len(prof.AllowedExtKeyUsage) > 0 && !containsString(prof.AllowedExtKeyUsage, "serverAuth") {
		return x509.KeyUsageDigitalSignature
	}
	return leafKeyUsage(nil)
}

// policyOIDs parses dotted-OID strings into asn1.ObjectIdentifiers for the
// certificatePolicies extension (the deprecated x509 field).
func policyOIDs(dotted []string) ([]asn1.ObjectIdentifier, error) {
	var out []asn1.ObjectIdentifier
	for _, s := range dotted {
		oid, err := parseOID(s)
		if err != nil {
			return nil, fmt.Errorf("crypto: certificate policy OID %q: %w", s, err)
		}
		out = append(out, oid)
	}
	return out, nil
}

// modernPolicyOIDs parses dotted-OID strings into x509.OID for the Go 1.22+
// Certificate.Policies field.
func modernPolicyOIDs(dotted []string) ([]x509.OID, error) {
	var out []x509.OID
	for _, s := range dotted {
		oid, err := x509.ParseOID(s)
		if err != nil {
			return nil, fmt.Errorf("crypto: certificate policy OID %q: %w", s, err)
		}
		out = append(out, oid)
	}
	return out, nil
}

// dnsSuffixPermitted reports whether name is exactly or under one of the suffixes
// (exact-or-subdomain), the same predicate the CA name-constraint uses.
func dnsSuffixPermitted(name string, suffixes []string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for _, suf := range suffixes {
		suf = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(trimLeadingDot(suf))), ".")
		if suf == "" {
			continue
		}
		if name == suf || hasDotSuffix(name, suf) {
			return true
		}
	}
	return false
}

func leafSANPolicyConfigured(prof LeafProfile) bool {
	return len(prof.PermittedDNSSuffixes)+len(prof.PermittedIPCIDRs)+len(prof.PermittedEmailDomains)+len(prof.PermittedURIPrefixes) > 0
}

func parseLeafCIDRs(cidrs []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR prefix: %w", raw, err)
		}
		out = append(out, network)
	}
	return out, nil
}

func ipInCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	for _, network := range cidrs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func emailDomainPermitted(email string, domains []string) bool {
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return false
	}
	return dnsSuffixPermitted(email[at+1:], domains)
}

func uriPrefixPermitted(uri string, prefixes []string) bool {
	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" && strings.HasPrefix(uri, prefix) {
			return true
		}
	}
	return false
}

// VerifyLeafSignedByCA reports whether leafDER was signed by the CA in caDER. It
// is the boundary helper callers use to confirm an issued certificate chains to
// its CA without importing crypto/x509 themselves (AN-3).
func VerifyLeafSignedByCA(leafDER, caDER []byte) error {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("crypto: parse leaf: %w", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fmt.Errorf("crypto: parse CA: %w", err)
	}
	return leaf.CheckSignatureFrom(ca)
}

// VerifyCertKeyMatchPEM reports whether a PEM certificate and a PEM private key form
// a USABLE TLS identity — i.e. the key is the certificate's private key. It is the
// boundary helper a caller uses to prove a "cert + key" bundle is loadable as a TLS
// keypair (the dynamic PKI secret's GAP-004 guarantee) without importing crypto/tls
// itself (AN-3). It returns a non-nil error when the pair does not load or does not
// match.
func VerifyCertKeyMatchPEM(certPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("crypto: certificate and key are not a usable TLS identity: %w", err)
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("crypto: serial: %w", err)
	}
	return serial, nil
}

// asErr is errors.As, kept local so the boundary's typed-error checks read
// crypto-internally without callers importing errors against crypto's types.
func asErr(err error, target any) bool { return errors.As(err, target) }

// parseOID parses a dotted object identifier ("2.23.140.1.2.1").
func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a dotted OID")
	}
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID arc %q", p)
		}
		oid = append(oid, n)
	}
	return oid, nil
}

func trimLeadingDot(s string) string { return strings.TrimPrefix(s, ".") }

func hasDotSuffix(name, suffix string) bool { return strings.HasSuffix(name, "."+suffix) }

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
