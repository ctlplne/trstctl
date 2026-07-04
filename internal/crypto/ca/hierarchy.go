// SPDX-License-Identifier: MPL-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

// This file adds private/enterprise CA hierarchy support (F48) inside the AN-3
// crypto boundary: a CA can be a self-signed root or an intermediate signed by a
// parent, carries name-constraint / path-length / EKU policy, issues end-entity
// certificates enforcing those constraints, and can cross-sign another CA. Like
// Authority, the CA holds its signing key in-process as the reference path; in
// production the key is custodied by the signer/HSM (AN-4) behind this boundary.
// Callers outside the boundary use the crypto-free results and never name
// crypto/*.

// CASpec describes a CA to create: its subject, the DNS name constraints it
// permits, its remaining path length (sub-CA depth; <0 means unset), the extended
// key usages it permits on issued certificates, and its validity.
type CASpec struct {
	CommonName          string
	PermittedDNSDomains []string
	MaxPathLen          int
	EKUs                []string
	TTL                 time.Duration
}

// CA is a certificate authority in a hierarchy: its certificate, signing key,
// chain to the root, and policy. It signs intermediates and end-entity
// certificates and enforces its constraints. The signing key is held in a locked
// secret buffer (mlock + MADV_DONTDUMP, AN-8) and reconstructed only for the
// instant of each signature (CRYPTO-005); the full HSM/signer custody is
// EXC-CRYPTO-01.
type CA struct {
	cert     *x509.Certificate
	der      []byte
	key      *lockedKey
	chainDER [][]byte // this cert first, then ancestors up to the root

	permittedDNS []string
	maxPathLen   int // remaining sub-CA depth; <0 means unset
	ekus         []x509.ExtKeyUsage
}

// Destroy zeroizes and releases this CA's locked signing key. It is idempotent.
// Callers that retire a CA (or a Manager dropping a CA from memory) should call
// it so the key material does not linger (AN-8).
func (c *CA) Destroy() { c.key.destroy() }

const (
	defaultRootTTL = 10 * 365 * 24 * time.Hour
	defaultCATTL   = 5 * 365 * 24 * time.Hour
)

// NewRoot creates a self-signed root CA.
func NewRoot(spec CASpec) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ttl := spec.TTL
	if ttl <= 0 {
		ttl = defaultRootTTL
	}
	// Self-signed: the new key signs its own certificate. Wrap it in a locked
	// buffer first, then sign through the buffer so the unprotected key is parsed
	// only for the signature (AN-8 / CRYPTO-005).
	locked, err := newLockedKey(key)
	if err != nil {
		return nil, err
	}
	der, cert, err := signCACert(spec.CommonName, spec.PermittedDNSDomains, spec.MaxPathLen, spec.EKUs, ttl, nil, locked, locked.public())
	if err != nil {
		locked.destroy()
		return nil, err
	}
	return &CA{
		cert: cert, der: der, key: locked, chainDER: [][]byte{der},
		permittedDNS: spec.PermittedDNSDomains, maxPathLen: spec.MaxPathLen, ekus: ekusFromStrings(spec.EKUs),
	}, nil
}

// CreateIntermediate signs an intermediate CA under c. It is rejected if c's path
// length is exhausted. The child's path length is one less than c's, and it
// inherits c's name constraints and EKU policy unless the spec narrows them.
func (c *CA) CreateIntermediate(spec CASpec) (*CA, error) {
	if c.maxPathLen == 0 {
		return nil, fmt.Errorf("ca: path-length constraint exhausted: %q may not issue sub-CAs", c.cert.Subject.CommonName)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	childPathLen := -1
	if c.maxPathLen > 0 {
		childPathLen = c.maxPathLen - 1
	}
	permitted := spec.PermittedDNSDomains
	if len(permitted) == 0 {
		permitted = c.permittedDNS
	}
	ekus := spec.EKUs
	if len(ekus) == 0 {
		ekus = ekuStrings(c.ekus)
	}
	ttl := spec.TTL
	if ttl <= 0 {
		ttl = defaultCATTL
	}
	locked, err := newLockedKey(key)
	if err != nil {
		return nil, err
	}
	// Signed by the parent (c): the parent's locked key signs the child's cert over
	// the child's public key.
	der, cert, err := signCACert(spec.CommonName, permitted, childPathLen, ekus, ttl, c.cert, c.key, locked.public())
	if err != nil {
		locked.destroy()
		return nil, err
	}
	return &CA{
		cert: cert, der: der, key: locked, chainDER: append([][]byte{der}, c.chainDER...),
		permittedDNS: permitted, maxPathLen: childPathLen, ekus: ekusFromStrings(ekus),
	}, nil
}

// IssueLeaf validates a CSR and signs an end-entity certificate, enforcing the
// CA's name constraints (every SAN must be permitted) and EKU policy. The
// returned PEM is the leaf followed by this CA's chain to the root.
//
// It is shorthand for IssueLeafWithProfile with the empty LeafProfile, preserving
// the in-process reference shape for callers that have no served revocation
// infrastructure (tests, breakglass). The served hierarchy path supplies a
// populated profile so the leaf carries CRL DP, AIA, certificatePolicies, and a
// bounded validity — see IssueLeafWithProfile (PKIGOV-002).
func (c *CA) IssueLeaf(csrDER []byte, ttl time.Duration) (Issued, error) {
	return c.IssueLeafWithProfile(csrDER, ttl, boundarycrypto.LeafProfile{})
}

// IssueLeafWithProfile signs an end-entity certificate from a CSR through the SAME
// served LeafProfile machinery as the broker issuance path
// (crypto.SignLeafFromCSRWithProfile), so a hierarchy-issued leaf carries the
// identical RFC 5280 / CA-Browser-Forum shape: the Subject Key Identifier and
// Authority Key Identifier, the revocation pointers (CRL distribution points), the
// AIA (OCSP responder + CA-issuers), the certificatePolicies OIDs, a bounded
// validity ceiling, the EKU policy, and the DNS name constraints (PKIGOV-002). The
// leaf signing is not duplicated here — it is delegated to the crypto boundary's
// single leaf signer, which also verifies the issued certificate against this CA
// before returning it (fail closed).
//
// This CA's own lane is folded into the supplied profile so a hierarchy leaf can
// never be issued outside the CA's name-constraint / EKU policy even when the
// caller's profile is more permissive: the CA's permittedDNS is intersected into
// the profile's permitted DNS suffixes (a CA with constraints clamps them), and
// the CA's EKU policy supplies the allowed-EKU set when the profile names none.
// The returned PEM is the leaf followed by this CA's chain to the root.
func (c *CA) IssueLeafWithProfile(csrDER []byte, ttl time.Duration, prof boundarycrypto.LeafProfile) (Issued, error) {
	prof = c.applyCALane(prof)
	signer, err := c.digestSigner()
	if err != nil {
		return Issued{}, err
	}
	defer signer.Destroy()
	leafDER, err := boundarycrypto.SignLeafFromCSRWithProfile(c.der, signer, csrDER, ttl, prof)
	if err != nil {
		return Issued{}, fmt.Errorf("ca: issue leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return Issued{}, fmt.Errorf("ca: parse issued leaf: %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	out = append(out, c.ChainPEM()...)
	return Issued{CertificatePEM: out, Serial: leaf.SerialNumber.Text(16), NotAfter: leaf.NotAfter}, nil
}

// applyCALane folds this CA's own name-constraint and EKU policy into prof so the
// issued leaf is clamped to the CA's lane regardless of the caller-supplied
// profile. A CA that permits no DNS domains and no EKUs imposes no extra clamp
// (the profile governs alone); a CA with constraints narrows the profile to them.
func (c *CA) applyCALane(prof boundarycrypto.LeafProfile) boundarycrypto.LeafProfile {
	if len(c.permittedDNS) > 0 {
		if len(prof.PermittedDNSSuffixes) == 0 {
			prof.PermittedDNSSuffixes = append([]string(nil), c.permittedDNS...)
		} else {
			prof.PermittedDNSSuffixes = intersectDNS(prof.PermittedDNSSuffixes, c.permittedDNS)
		}
	}
	if len(prof.AllowedExtKeyUsage) == 0 {
		if ekus := ekuStrings(c.ekus); len(ekus) > 0 {
			prof.AllowedExtKeyUsage = ekus
		}
	}
	return prof
}

// digestSigner reconstructs a boundary DigestSigner over this CA's locked PKCS#8
// signing key so the leaf signer (crypto.SignLeafFromCSRWithProfile) can drive it
// without leaving the AN-3 boundary. The returned signer holds its own locked
// secret buffer (the private key materializes in the clear only for the instant of
// each SignDigest, AN-8); the caller MUST Destroy it when done. The in-process CA
// key is always ECDSA-P256 (NewRoot/CreateIntermediate generate P256).
func (c *CA) digestSigner() (*boundarycrypto.LockedSigner, error) {
	der := c.key.der.Bytes()
	if der == nil {
		return nil, fmt.Errorf("ca: CA key has been destroyed")
	}
	signer, err := boundarycrypto.NewLockedSignerFromPKCS8(boundarycrypto.ECDSAP256, der)
	if err != nil {
		return nil, fmt.Errorf("ca: load CA signing key: %w", err)
	}
	return signer, nil
}

// CrossSign issues a cross-certificate for another CA's certificate: it carries
// that CA's subject and public key but is signed by this CA, so relying parties
// that trust this CA also trust the cross-signed one.
//
// A cross-certificate is a fully privileged CA certificate, so it must not be
// issued unconstrained (PKIGOV-004). It carries forward the target's path-length
// basic constraint and dNSName name constraints, and additionally clamps them to
// this signing CA's own lane: the cross-cert's permitted DNS domains are the
// intersection with this CA's name constraints, and its sub-CA depth is the more
// restrictive of the target's own pathLen and this CA's remaining depth. This
// prevents a cross-signature from widening the trust the relying party already
// extended to this CA (e.g. cross-signing a name-unconstrained or deeper CA must
// not let it issue names or depths this CA may not).
func (c *CA) CrossSign(otherCertDER []byte) ([]byte, error) {
	other, err := x509.ParseCertificate(otherCertDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse cross-sign target: %w", err)
	}
	if !other.IsCA {
		return nil, fmt.Errorf("ca: cross-sign target %q is not a CA certificate", other.Subject.CommonName)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	// Path length: cross-signing re-issues a peer CA at the same trust tier, so the
	// target's own depth is carried — but clamped to this signing CA's remaining
	// depth so the cross-cert can never grant MORE sub-CA depth than this CA itself
	// holds. The result is the more restrictive (smaller) of the two whenever both
	// are set; if the target is unset it is pinned to this CA's depth.
	pathLen, hasPathLen := crossPathLen(other)
	if c.maxPathLen >= 0 {
		if !hasPathLen || c.maxPathLen < pathLen {
			pathLen, hasPathLen = c.maxPathLen, true
		}
	}

	// Name constraints: carry the target's permitted dNSName set, then intersect
	// with this CA's own permitted set so the cross-cert can never permit a name
	// this CA itself may not.
	permitted := intersectDNS(other.PermittedDNSDomains, c.permittedDNS)

	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     other.Subject,
		NotBefore:                   other.NotBefore,
		NotAfter:                    other.NotAfter,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		PermittedDNSDomains:         permitted,
		PermittedDNSDomainsCritical: len(permitted) > 0,
	}
	if hasPathLen {
		tmpl.MaxPathLen = pathLen
		tmpl.MaxPathLenZero = pathLen == 0
	}
	var crossDER []byte
	if err := c.key.sign(func(priv *ecdsa.PrivateKey) error {
		var e error
		crossDER, e = x509.CreateCertificate(rand.Reader, tmpl, c.cert, other.PublicKey, priv)
		return e
	}); err != nil {
		return nil, fmt.Errorf("ca: cross-sign: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crossDER}), nil
}

// crossPathLen extracts the basic-constraints path-length from a parsed CA
// certificate, distinguishing "explicitly zero" from "unset". Go's x509 sets
// MaxPathLen=0 with MaxPathLenZero=true for an explicit zero, and leaves
// MaxPathLen=0/MaxPathLenZero=false (or MaxPathLen<0) when the constraint is
// absent.
func crossPathLen(cert *x509.Certificate) (int, bool) {
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		return cert.MaxPathLen, true
	}
	return 0, false
}

// intersectDNS returns the dNSName name-constraint set the cross-cert may permit:
// the target's permitted set restricted to what the signing CA itself permits. If
// the signing CA is unconstrained, the target's set carries forward unchanged. If
// the target is unconstrained, it is narrowed to the signing CA's set.
func intersectDNS(target, signer []string) []string {
	if len(signer) == 0 {
		return append([]string(nil), target...)
	}
	if len(target) == 0 {
		return append([]string(nil), signer...)
	}
	var out []string
	for _, t := range target {
		if dnsPermitted(strings.TrimPrefix(t, "."), signer) || containsFold(signer, t) {
			out = append(out, t)
		}
	}
	return out
}

// containsFold reports whether set contains v, ignoring a leading constraint dot.
func containsFold(set []string, v string) bool {
	v = strings.TrimPrefix(v, ".")
	for _, s := range set {
		if strings.TrimPrefix(s, ".") == v {
			return true
		}
	}
	return false
}

// CertificatePEM returns this CA's certificate in PEM form.
func (c *CA) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// CertificateDER returns this CA's certificate in DER form.
func (c *CA) CertificateDER() []byte { return c.der }

// ChainPEM returns this CA's certificate followed by its ancestors, PEM-encoded.
func (c *CA) ChainPEM() []byte {
	var out []byte
	for _, der := range c.chainDER {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

// CommonName is the CA's subject common name.
func (c *CA) CommonName() string { return c.cert.Subject.CommonName }

// Serial is the CA certificate's serial number in hex.
func (c *CA) Serial() string { return c.cert.SerialNumber.Text(16) }

// NotAfter is the CA certificate's expiry.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// MaxPathLen is the CA's remaining sub-CA depth (<0 means unset).
func (c *CA) MaxPathLen() int { return c.maxPathLen }

// PermittedDNSDomains returns the CA's permitted DNS name constraints.
func (c *CA) PermittedDNSDomains() []string { return c.permittedDNS }

// signCACert builds and signs a CA certificate. When parent is nil it is
// self-signed (a root) and the signing key is the new CA's own (passed as
// signerKey); otherwise it is signed by the parent (an intermediate) whose locked
// signing key is signerKey. The private key is reconstructed from its locked
// buffer only for the instant of CreateCertificate (AN-8 / CRYPTO-005).
func signCACert(commonName string, permitted []string, maxPathLen int, ekus []string, ttl time.Duration, parent *x509.Certificate, signerKey *lockedKey, pub *ecdsa.PublicKey) ([]byte, *x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: commonName},
		NotBefore:                   now.Add(-time.Minute),
		NotAfter:                    now.Add(ttl),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		PermittedDNSDomains:         permitted,
		PermittedDNSDomainsCritical: len(permitted) > 0,
	}
	if maxPathLen >= 0 {
		tmpl.MaxPathLen = maxPathLen
		tmpl.MaxPathLenZero = maxPathLen == 0
	}
	if e := ekusFromStrings(ekus); len(e) > 0 {
		tmpl.ExtKeyUsage = e
	}
	issuer := parent
	if issuer == nil { // self-signed root: the template is its own issuer
		issuer = tmpl
	}
	var der []byte
	if err := signerKey.sign(func(priv *ecdsa.PrivateKey) error {
		var e error
		der, e = x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, priv)
		return e
	}); err != nil {
		return nil, nil, fmt.Errorf("ca: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return der, cert, nil
}

// dnsPermitted reports whether name is within one of the permitted DNS domains
// (exact match or a subdomain), per RFC 5280 name constraints.
func dnsPermitted(name string, permitted []string) bool {
	for _, p := range permitted {
		p = strings.TrimPrefix(p, ".")
		if name == p || strings.HasSuffix(name, "."+p) {
			return true
		}
	}
	return false
}

func ekusFromStrings(names []string) []x509.ExtKeyUsage {
	var out []x509.ExtKeyUsage
	for _, n := range names {
		switch n {
		case "serverAuth":
			out = append(out, x509.ExtKeyUsageServerAuth)
		case "clientAuth":
			out = append(out, x509.ExtKeyUsageClientAuth)
		case "codeSigning":
			out = append(out, x509.ExtKeyUsageCodeSigning)
		case "emailProtection":
			out = append(out, x509.ExtKeyUsageEmailProtection)
		case "any":
			out = append(out, x509.ExtKeyUsageAny)
		}
	}
	return out
}

func ekuStrings(ekus []x509.ExtKeyUsage) []string {
	var out []string
	for _, e := range ekus {
		switch e {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "emailProtection")
		case x509.ExtKeyUsageAny:
			out = append(out, "any")
		}
	}
	return out
}
