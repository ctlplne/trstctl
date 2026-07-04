// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"sort"
	"time"
)

const (
	defaultHierarchyRootTTL = 10 * 365 * 24 * time.Hour
	defaultHierarchyCATTL   = 5 * 365 * 24 * time.Hour
)

// HierarchyCAProfile is the crypto-boundary representation of a served private
// CA certificate. The signer passed to the functions below may be an isolated
// signing-service RemoteSigner, so the CA private key never enters the control
// plane.
type HierarchyCAProfile struct {
	CommonName          string
	PermittedDNSDomains []string
	MaxPathLen          int
	EKUs                []string
	TTL                 time.Duration
}

// IssuedHierarchyCA is the public result of CA certificate creation. It contains
// the certificate only; private key material remains inside the supplied signer.
type IssuedHierarchyCA struct {
	CommonName          string
	CertificateDER      []byte
	CertificatePEM      []byte
	Serial              string
	NotAfter            time.Time
	MaxPathLen          int
	PermittedDNSDomains []string
	EKUs                []string
}

// SelfSignedHierarchyCA creates a self-signed CA certificate using signer. The
// private key is signer-held; only the digest to sign crosses the signer boundary.
func SelfSignedHierarchyCA(signer DigestSigner, profile HierarchyCAProfile) (IssuedHierarchyCA, error) {
	if profile.TTL <= 0 {
		profile.TTL = defaultHierarchyRootTTL
	}
	return signHierarchyCA(signer, signer.Public(), nil, profile)
}

// SignIntermediateHierarchyCA creates an intermediate CA certificate: childPublic
// is the public key of the signer-held child key, and parentSigner signs the
// certificate under parentCertDER.
func SignIntermediateHierarchyCA(parentCertDER []byte, parentSigner DigestSigner, childPublic PublicKey, profile HierarchyCAProfile) (IssuedHierarchyCA, error) {
	parent, err := x509.ParseCertificate(parentCertDER)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: parse parent CA: %w", err)
	}
	parentHasPathLen := parent.MaxPathLen > 0 || parent.MaxPathLenZero
	if parentHasPathLen && parent.MaxPathLen == 0 {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: parent CA path-length constraint is exhausted")
	}
	if len(profile.PermittedDNSDomains) == 0 {
		profile.PermittedDNSDomains = append([]string(nil), parent.PermittedDNSDomains...)
	}
	if len(profile.EKUs) == 0 {
		profile.EKUs = extKeyUsageStrings(parent.ExtKeyUsage)
	}
	if parentHasPathLen {
		childPathLen := parent.MaxPathLen - 1
		if profile.MaxPathLen >= 0 && profile.MaxPathLen < childPathLen {
			childPathLen = profile.MaxPathLen
		}
		profile.MaxPathLen = childPathLen
	}
	if profile.TTL <= 0 {
		profile.TTL = defaultHierarchyCATTL
	}
	if notAfter := time.Now().Add(profile.TTL); notAfter.After(parent.NotAfter) {
		profile.TTL = time.Until(parent.NotAfter)
	}
	return signHierarchyCA(parentSigner, childPublic, parent, profile)
}

// SignIntermediateHierarchyCAFromCSR creates an intermediate CA certificate over a
// caller-held CA key. The CSR is verified inside the crypto boundary, the public key
// from the CSR becomes the subordinate CA public key, and parentSigner signs the
// resulting CA certificate. This is the SPIRE UpstreamAuthority path: SPIRE keeps its
// local CA private key, while trstctl signs the intermediate certificate through the
// isolated signer.
func SignIntermediateHierarchyCAFromCSR(parentCertDER []byte, parentSigner DigestSigner, csrDER []byte, profile HierarchyCAProfile) (IssuedHierarchyCA, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: parse intermediate CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: verify intermediate CSR signature: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: marshal intermediate CSR public key: %w", err)
	}
	if profile.CommonName == "" {
		profile.CommonName = csr.Subject.CommonName
	}
	return SignIntermediateHierarchyCA(parentCertDER, parentSigner, PublicKey{DER: pubDER}, profile)
}

// VerifyImportedOfflineRoot validates a public root certificate produced outside
// trstctl's hot path. It never accepts private-key bytes; callers pass only the
// certificate DER. The root must be a self-signed CA with certificate-signing
// capability and must match the operator-reviewed profile bound to the ceremony.
func VerifyImportedOfflineRoot(certDER []byte, profile HierarchyCAProfile) (IssuedHierarchyCA, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: parse offline root: %w", err)
	}
	if err := verifyCAUsable(cert, "offline root"); err != nil {
		return IssuedHierarchyCA{}, err
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: offline root is not self-signed: %w", err)
	}
	if err := verifyImportedProfile(cert, profile); err != nil {
		return IssuedHierarchyCA{}, err
	}
	return hierarchyResultFromCert(cert), nil
}

// VerifyOfflineSignedIntermediate validates an intermediate CA certificate signed
// by an offline parent root. The certificate must chain to parentCertDER, obey the
// parent's path-length boundary, match the reviewed profile, and contain exactly
// the public key held by the served signer handle.
func VerifyOfflineSignedIntermediate(parentCertDER, certDER []byte, signerPublic PublicKey, profile HierarchyCAProfile) (IssuedHierarchyCA, error) {
	parent, err := x509.ParseCertificate(parentCertDER)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: parse offline parent root: %w", err)
	}
	if err := verifyCAUsable(parent, "offline parent root"); err != nil {
		return IssuedHierarchyCA{}, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: parse offline-signed intermediate: %w", err)
	}
	if err := verifyCAUsable(cert, "offline-signed intermediate"); err != nil {
		return IssuedHierarchyCA{}, err
	}
	if err := cert.CheckSignatureFrom(parent); err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: intermediate is not signed by offline root: %w", err)
	}
	if err := verifyChildPathLen(parent, cert); err != nil {
		return IssuedHierarchyCA{}, err
	}
	if cert.NotAfter.After(parent.NotAfter) {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: intermediate outlives offline root")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: marshal intermediate public key: %w", err)
	}
	if !bytes.Equal(pubDER, signerPublic.DER) {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: intermediate public key does not match signer-held key")
	}
	if err := verifyImportedProfile(cert, profile); err != nil {
		return IssuedHierarchyCA{}, err
	}
	return hierarchyResultFromCert(cert), nil
}

// VerifyImportedCAChain validates an existing CA certificate chain whose private
// key is already custodied by the signer. chainDER[0] is the imported issuing CA
// certificate; any following certificates must build to a self-signed root. The
// first certificate's public key must match signerPublic, proving the signer-held
// handle can actually operate this imported CA without moving private bytes into
// the control plane.
func VerifyImportedCAChain(chainDER [][]byte, signerPublic PublicKey, profile HierarchyCAProfile) (IssuedHierarchyCA, string, error) {
	if len(chainDER) == 0 {
		return IssuedHierarchyCA{}, "", fmt.Errorf("crypto: imported CA chain is empty")
	}
	certs := make([]*x509.Certificate, 0, len(chainDER))
	for i, der := range chainDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return IssuedHierarchyCA{}, "", fmt.Errorf("crypto: parse imported CA chain certificate %d: %w", i, err)
		}
		if err := verifyCAUsable(cert, "imported CA chain certificate"); err != nil {
			return IssuedHierarchyCA{}, "", err
		}
		certs = append(certs, cert)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(certs[0].PublicKey)
	if err != nil {
		return IssuedHierarchyCA{}, "", fmt.Errorf("crypto: marshal imported CA public key: %w", err)
	}
	if !bytes.Equal(pubDER, signerPublic.DER) {
		return IssuedHierarchyCA{}, "", fmt.Errorf("crypto: imported CA public key does not match signer-held key")
	}
	if err := verifyImportedProfile(certs[0], profile); err != nil {
		return IssuedHierarchyCA{}, "", err
	}
	if len(certs) == 1 {
		if err := certs[0].CheckSignatureFrom(certs[0]); err != nil {
			return IssuedHierarchyCA{}, "", fmt.Errorf("crypto: imported root is not self-signed: %w", err)
		}
		return hierarchyResultFromCert(certs[0]), "root", nil
	}
	for i := 0; i < len(certs)-1; i++ {
		child, parent := certs[i], certs[i+1]
		if err := child.CheckSignatureFrom(parent); err != nil {
			return IssuedHierarchyCA{}, "", fmt.Errorf("crypto: imported CA chain certificate %d is not signed by certificate %d: %w", i, i+1, err)
		}
		if err := verifyChildPathLen(parent, child); err != nil {
			return IssuedHierarchyCA{}, "", err
		}
		if child.NotAfter.After(parent.NotAfter) {
			return IssuedHierarchyCA{}, "", fmt.Errorf("crypto: imported CA chain certificate %d outlives issuer", i)
		}
	}
	root := certs[len(certs)-1]
	if err := root.CheckSignatureFrom(root); err != nil {
		return IssuedHierarchyCA{}, "", fmt.Errorf("crypto: imported CA chain root is not self-signed: %w", err)
	}
	return hierarchyResultFromCert(certs[0]), "intermediate", nil
}

func signHierarchyCA(signer DigestSigner, subjectPublic PublicKey, issuer *x509.Certificate, profile HierarchyCAProfile) (IssuedHierarchyCA, error) {
	if profile.CommonName == "" {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: CA common name is required")
	}
	if profile.TTL <= 0 {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: CA TTL must be positive")
	}
	adapter, err := newX509Signer(signer)
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	pub, err := parsePKIXPublicKey(subjectPublic)
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	ski, err := subjectKeyID(pub)
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	knownEKUs, customEKUs, err := caExtKeyUsage(profile.EKUs)
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: profile.CommonName},
		NotBefore:                   now.Add(-time.Minute),
		NotAfter:                    now.Add(profile.TTL),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		SubjectKeyId:                ski,
		PermittedDNSDomains:         profile.PermittedDNSDomains,
		PermittedDNSDomainsCritical: len(profile.PermittedDNSDomains) > 0,
		ExtKeyUsage:                 knownEKUs,
		UnknownExtKeyUsage:          customEKUs,
	}
	if profile.MaxPathLen >= 0 {
		tmpl.MaxPathLen = profile.MaxPathLen
		tmpl.MaxPathLenZero = profile.MaxPathLen == 0
	}
	selfSigned := issuer == nil
	if selfSigned {
		issuer = tmpl
		tmpl.AuthorityKeyId = ski
	} else if len(issuer.SubjectKeyId) > 0 {
		tmpl.AuthorityKeyId = issuer.SubjectKeyId
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, adapter)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: sign CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	verifyIssuer := issuer
	if selfSigned {
		verifyIssuer = cert
	}
	if err := cert.CheckSignatureFrom(verifyIssuer); err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: issued CA failed verification: %w", err)
	}
	return IssuedHierarchyCA{
		CommonName:          cert.Subject.CommonName,
		CertificateDER:      der,
		CertificatePEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:              cert.SerialNumber.Text(16),
		NotAfter:            cert.NotAfter,
		MaxPathLen:          profile.MaxPathLen,
		PermittedDNSDomains: append([]string(nil), profile.PermittedDNSDomains...),
		EKUs:                append([]string(nil), profile.EKUs...),
	}, nil
}

func verifyCAUsable(cert *x509.Certificate, label string) error {
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return fmt.Errorf("crypto: %s is not a valid CA certificate", label)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("crypto: %s is not currently valid", label)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("crypto: %s is missing keyCertSign usage", label)
	}
	if cert.SerialNumber == nil {
		return fmt.Errorf("crypto: %s has no serial number", label)
	}
	return nil
}

func verifyChildPathLen(parent, child *x509.Certificate) error {
	parentHasPathLen := parent.MaxPathLen > 0 || parent.MaxPathLenZero
	if !parentHasPathLen {
		return nil
	}
	if parent.MaxPathLen == 0 {
		return fmt.Errorf("crypto: offline root path-length constraint is exhausted")
	}
	childHasPathLen := child.MaxPathLen > 0 || child.MaxPathLenZero
	if !childHasPathLen {
		return fmt.Errorf("crypto: offline-signed intermediate is missing path-length constraint")
	}
	if child.MaxPathLen > parent.MaxPathLen-1 {
		return fmt.Errorf("crypto: offline-signed intermediate path-length exceeds offline root")
	}
	return nil
}

func verifyImportedProfile(cert *x509.Certificate, profile HierarchyCAProfile) error {
	if profile.CommonName != "" && cert.Subject.CommonName != profile.CommonName {
		return fmt.Errorf("crypto: imported CA common name %q does not match ceremony profile %q", cert.Subject.CommonName, profile.CommonName)
	}
	if profile.MaxPathLen >= 0 {
		hasPathLen := cert.MaxPathLen > 0 || cert.MaxPathLenZero
		if !hasPathLen {
			return fmt.Errorf("crypto: imported CA is missing path-length constraint")
		}
		if cert.MaxPathLen != profile.MaxPathLen {
			return fmt.Errorf("crypto: imported CA max_path_len %d does not match ceremony profile %d", cert.MaxPathLen, profile.MaxPathLen)
		}
	}
	if len(profile.PermittedDNSDomains) > 0 && !sameStringSet(profile.PermittedDNSDomains, cert.PermittedDNSDomains) {
		return fmt.Errorf("crypto: imported CA permitted DNS domains do not match ceremony profile")
	}
	if len(profile.EKUs) > 0 && !sameStringSet(profile.EKUs, extKeyUsageStrings(cert.ExtKeyUsage)) {
		return fmt.Errorf("crypto: imported CA extended key usages do not match ceremony profile")
	}
	return nil
}

func hierarchyResultFromCert(cert *x509.Certificate) IssuedHierarchyCA {
	maxPathLen := cert.MaxPathLen
	if cert.MaxPathLen == 0 && !cert.MaxPathLenZero {
		maxPathLen = -1
	}
	return IssuedHierarchyCA{
		CommonName:          cert.Subject.CommonName,
		CertificateDER:      append([]byte(nil), cert.Raw...),
		CertificatePEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		Serial:              cert.SerialNumber.Text(16),
		NotAfter:            cert.NotAfter,
		MaxPathLen:          maxPathLen,
		PermittedDNSDomains: append([]string(nil), cert.PermittedDNSDomains...),
		EKUs:                extKeyUsageStrings(cert.ExtKeyUsage),
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func parsePKIXPublicKey(pub PublicKey) (any, error) {
	if len(pub.DER) == 0 {
		return nil, fmt.Errorf("crypto: public key is empty")
	}
	parsed, err := x509.ParsePKIXPublicKey(pub.DER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse public key: %w", err)
	}
	return parsed, nil
}

func extKeyUsageStrings(usages []x509.ExtKeyUsage) []string {
	out := make([]string, 0, len(usages))
	for _, u := range usages {
		switch u {
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

func caExtKeyUsage(names []string) ([]x509.ExtKeyUsage, []asn1.ObjectIdentifier, error) {
	if len(names) == 0 {
		return nil, nil, nil
	}
	var known []x509.ExtKeyUsage
	var custom []asn1.ObjectIdentifier
	for _, name := range names {
		if usage, ok := knownExtKeyUsage(name); ok {
			known = append(known, usage)
			continue
		}
		oid, err := parseDottedOID(name)
		if err != nil {
			return nil, nil, fmt.Errorf("unsupported CA extended key usage %q", name)
		}
		custom = append(custom, oid)
	}
	return known, custom, nil
}
