// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"maps"
	"strings"
)

// ErrCSRNotBoundToIdentity is returned when a CSR requests an identifier that the
// authenticated enrollment certificate does not itself assert.
var ErrCSRNotBoundToIdentity = errors.New("crypto: CSR identifiers are not authorized by the authenticated identity")

// enrollmentIdentity retains the complete subject and typed GeneralNames from
// the PKCS#10. Reconstructing a name from pkix.Name drops some RDNs and their
// grouping. Looking only at DNSNames and EmailAddresses also loses otherNames.
type enrollmentIdentity struct {
	subject []byte
	san     []byte
}

func enrollmentIdentityFromCSR(csr *x509.CertificateRequest) enrollmentIdentity {
	return enrollmentIdentity{subject: bytes.Clone(csr.RawSubject), san: bytes.Clone(enrollmentSANExtension(csr.Extensions))}
}

func enrollmentSANExtension(extensions []pkix.Extension) []byte {
	for _, ext := range extensions {
		if ext.Id.Equal(oidSubjectAltNameExt) {
			return ext.Value
		}
	}
	return nil
}

// enrollmentSANs keeps the DER tag and value together so distinct GeneralName
// alternatives cannot match. DNS lookup is case-insensitive. Mailbox local
// parts and URI paths retain their original case.
func enrollmentSANs(der []byte) (map[string]int, error) {
	names := make(map[string]int)
	if der == nil {
		return names, nil
	}
	var values []asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &values); err != nil || len(rest) != 0 || len(values) == 0 {
		return nil, fmt.Errorf("%w: invalid subjectAltName", ErrCSRNotBoundToIdentity)
	}
	for _, v := range values {
		if v.Class != asn1.ClassContextSpecific || v.Tag > 8 {
			return nil, fmt.Errorf("%w: invalid GeneralName", ErrCSRNotBoundToIdentity)
		}
		key := string(v.FullBytes)
		if v.Tag == 2 && !v.IsCompound {
			key = "dns:" + strings.ToLower(string(v.Bytes))
		}
		names[key]++
	}
	return names, nil
}

func (id enrollmentIdentity) bind(authority *x509.Certificate, exactSANs bool) error {
	if authority == nil || len(id.subject) == 0 || !bytes.Equal(id.subject, authority.RawSubject) {
		return fmt.Errorf("%w: full subject differs from the authenticated certificate", ErrCSRNotBoundToIdentity)
	}
	requested, err := enrollmentSANs(id.san)
	if err != nil {
		return err
	}
	if len(requested) == 0 && strings.TrimSpace(authority.Subject.CommonName) == "" {
		return fmt.Errorf("%w: the CSR requests no identifiers", ErrCSRNotBoundToIdentity)
	}
	allowed, err := enrollmentSANs(enrollmentSANExtension(authority.Extensions))
	if err != nil {
		return err
	}
	if exactSANs {
		if !maps.Equal(requested, allowed) {
			return fmt.Errorf("%w: subjectAltName differs from the authenticated certificate", ErrCSRNotBoundToIdentity)
		}
		return nil
	}
	// CMP also permits a DNS name that equals the protection certificate's
	// subject CN. EST re-enrollment requires the original SANs themselves.
	if cn := strings.TrimSpace(authority.Subject.CommonName); cn != "" {
		allowed["dns:"+strings.ToLower(cn)]++
	}
	for name := range requested {
		if allowed[name] == 0 {
			return fmt.Errorf("%w: subjectAltName is outside the protection identity", ErrCSRNotBoundToIdentity)
		}
	}
	return nil
}

// CSRBoundToCertificateIdentity checks the full subject and authorized SANs
// for CMP enrollment under a verified protection certificate.
func CSRBoundToCertificateIdentity(csrDER []byte, authority *x509.Certificate) error {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("crypto: parse CSR for identity binding: %w", err)
	}
	return enrollmentIdentityFromCSR(csr).bind(authority, false)
}

// CSRInfoBoundToCertificateIdentity applies the same check to the signed name
// fields retained by the classical or opaque public-key inspector.
func CSRInfoBoundToCertificateIdentity(info CSRInfo, authority *x509.Certificate) error {
	return info.identity.bind(authority, false)
}

// CSRBoundToTLSClientIdentity requires the authenticated EST subject and SANs
// on the renewal CSR. The key may change and SAN order is immaterial.
func CSRBoundToTLSClientIdentity(state *tls.ConnectionState, csrDER []byte) error {
	if state == nil || len(state.PeerCertificates) == 0 {
		return errors.New("crypto: TLS client certificate required to bind the CSR")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("crypto: parse CSR for identity binding: %w", err)
	}
	return enrollmentIdentityFromCSR(csr).bind(state.PeerCertificates[0], true)
}

// TLSConnectionState is a small wrapper for tests and protocol packages that
// need a TLS peer state without importing crypto/tls outside the crypto boundary.
type TLSConnectionState struct {
	state *tls.ConnectionState
}

// ConnectionState exposes the wrapped TLS state for net/http request wiring.
func (s *TLSConnectionState) ConnectionState() *tls.ConnectionState {
	if s == nil {
		return nil
	}
	return s.state
}

// TLSStateWithPeerCertificates builds a TLS peer state from DER certificates.
// It is used by protocol tests and by callers that receive peer chains in a
// boundary-neutral form.
func TLSStateWithPeerCertificates(certsDER [][]byte) (*TLSConnectionState, error) {
	certs, err := parseCertificates(certsDER)
	if err != nil {
		return nil, err
	}
	return &TLSConnectionState{state: &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  certs,
		VerifiedChains:    [][]*x509.Certificate{certs},
	}}, nil
}

// VerifyTLSClientCertificate verifies a TLS client's leaf against DER trust
// anchors and returns the verified leaf's DER. The leaf must be issued directly
// by one of the anchors (no intermediate the client supplies is used) and must
// list clientAuth among its extended key usages: a leaf with no EKU extension or
// with anyExtendedKeyUsage is refused (CR-059). It keeps x509 verification inside
// internal/crypto (AN-3) while EST/KMIP-style protocols consume only request state
// and DER.
func VerifyTLSClientCertificate(state *tls.ConnectionState, rootsDER [][]byte) ([]byte, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, errors.New("crypto: TLS client certificate required")
	}
	roots, err := certPoolFromDER(rootsDER)
	if err != nil {
		return nil, err
	}
	leaf := state.PeerCertificates[0]
	if !leafListsClientAuth(leaf) {
		return nil, errors.New("crypto: TLS client certificate does not list clientAuth")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("crypto: verify TLS client certificate: %w", err)
	}
	return append([]byte(nil), leaf.Raw...), nil
}

// leafListsClientAuth reports whether the leaf names clientAuth and not
// anyExtendedKeyUsage, which the x509 verifier lets satisfy every usage.
func leafListsClientAuth(leaf *x509.Certificate) bool {
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageAny:
			return false
		case x509.ExtKeyUsageClientAuth:
			clientAuth = true
		}
	}
	return clientAuth
}

func parseCertificates(certsDER [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(certsDER))
	for i, der := range certsDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse certificate %d: %w", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func certPoolFromDER(certsDER [][]byte) (*x509.CertPool, error) {
	if len(certsDER) == 0 {
		return nil, errors.New("crypto: at least one trust anchor is required")
	}
	roots := x509.NewCertPool()
	certs, err := parseCertificates(certsDER)
	if err != nil {
		return nil, err
	}
	for _, cert := range certs {
		roots.AddCert(cert)
	}
	return roots, nil
}
