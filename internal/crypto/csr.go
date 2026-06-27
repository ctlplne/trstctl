package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
)

// CertificateRequestTemplate is a backend-agnostic PKCS#10 CSR template so
// callers never touch crypto/x509 directly (AN-3).
type CertificateRequestTemplate struct {
	CommonName    string
	DNSNames      []string
	RequestedEKUs []string
	// ChallengePassword is the PKCS#9 SCEP challengePassword attribute. It is used
	// only for client-side SCEP request construction and tests; server-side
	// validation still extracts the attribute from the signed CSR bytes.
	ChallengePassword []byte
	// ESTChannelBinding carries the EST tls-server-end-point channel-binding value
	// as a signed CSR attribute. It is used by EST clients/protocol tests so the
	// protocol package never imports crypto/x509 or ASN.1 directly (AN-3).
	ESTChannelBinding []byte
	// ExtraExtensions are CSR extension requests already DER-encoded by a helper
	// inside the crypto boundary. They let protocol-specific request proofs travel
	// in PKCS#10 without callers importing crypto/x509.
	ExtraExtensions []CertificateExtension
}

// CreateCertificateRequest builds and signs a CSR using signer. The private key
// is used only through the DigestSigner interface, so signer may be remote
// (for example the isolated signing service reached over UDS).
func CreateCertificateRequest(tmpl CertificateRequestTemplate, signer DigestSigner) ([]byte, error) {
	adapter, err := newX509Signer(signer)
	if err != nil {
		return nil, err
	}
	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: tmpl.CommonName},
		DNSNames: tmpl.DNSNames,
	}
	if len(tmpl.ChallengePassword) > 0 {
		req.Attributes = append(req.Attributes, pkix.AttributeTypeAndValueSET{ //nolint:staticcheck // PKCS#9 challengePassword is a CSR attribute, not an extension; x509 exposes no non-deprecated template field for it.
			Type: oidChallengePassword,
			Value: [][]pkix.AttributeTypeAndValue{{
				{Type: oidChallengePassword, Value: asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   asn1.TagUTF8String,
					Bytes: append([]byte(nil), tmpl.ChallengePassword...),
				}},
			}},
		})
	}
	if len(tmpl.ESTChannelBinding) > 0 {
		if err := appendESTChannelBindingAttribute(req, tmpl.ESTChannelBinding); err != nil {
			return nil, err
		}
	}
	if len(tmpl.RequestedEKUs) > 0 {
		ext, err := marshalExtKeyUsageExtension(tmpl.RequestedEKUs)
		if err != nil {
			return nil, err
		}
		req.ExtraExtensions = append(req.ExtraExtensions, ext)
	}
	if len(tmpl.ExtraExtensions) > 0 {
		exts, err := x509Extensions(tmpl.ExtraExtensions)
		if err != nil {
			return nil, err
		}
		req.ExtraExtensions = append(req.ExtraExtensions, exts...)
	}
	return x509.CreateCertificateRequest(rand.Reader, req, adapter)
}

// VerifyCertificateRequest parses a CSR and checks its self-signature.
func VerifyCertificateRequest(der []byte) error {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return err
	}
	return csr.CheckSignature()
}

// CSRInfo is the backend-agnostic view of a CSR a caller needs to validate it
// against a certificate profile (S8.1), so profile enforcement never imports
// crypto/x509 (AN-3).
type CSRInfo struct {
	KeyAlgorithm  string   // "RSA" | "ECDSA" | "Ed25519"
	KeyBits       int      // RSA modulus bits, ECDSA curve bits, or 256 for Ed25519
	DNSNames      []string // SAN dNSNames in the request
	CommonName    string
	RequestedEKUs []string // EKUs requested in the CSR's extensionRequest, if any
}

// InspectCSR parses a CSR (verifying its self-signature) and returns the
// profile-relevant attributes of its public key and subject. It is the single
// inspection seam used by profile validation.
func InspectCSR(der []byte) (CSRInfo, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return CSRInfo{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return CSRInfo{}, err
	}
	info := CSRInfo{DNSNames: csr.DNSNames, CommonName: csr.Subject.CommonName}
	ekus, err := extKeyUsageNamesFromExtensions(csr.Extensions)
	if err != nil {
		return CSRInfo{}, err
	}
	info.RequestedEKUs = ekus
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyAlgorithm, info.KeyBits = "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeyAlgorithm, info.KeyBits = "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		info.KeyAlgorithm, info.KeyBits = "Ed25519", 256
	default:
		info.KeyAlgorithm = "unknown"
	}
	if alg, found, err := HybridKeyAlgorithmFromExtensions(certificateExtensionsFromPKIX(csr.Extensions)); err != nil {
		return CSRInfo{}, err
	} else if found {
		info.KeyAlgorithm = alg
	}
	return info, nil
}

// x509Signer adapts a DigestSigner to the standard library's crypto.Signer so a
// (possibly remote) key can drive x509.CreateCertificateRequest. It lives inside
// the AN-3 boundary precisely so callers don't need crypto/x509.
type x509Signer struct {
	inner DigestSigner
	pub   crypto.PublicKey
	isRSA bool
}

func newX509Signer(inner DigestSigner) (*x509Signer, error) {
	pub, err := x509.ParsePKIXPublicKey(inner.Public().DER)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	_, isRSA := pub.(*rsa.PublicKey)
	return &x509Signer{inner: inner, pub: pub, isRSA: isRSA}, nil
}

func (a *x509Signer) Public() crypto.PublicKey { return a.pub }

func (a *x509Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	h, err := hashFromCrypto(opts.HashFunc())
	if err != nil {
		return nil, err
	}
	sopts := SignOptions{Hash: h}
	if a.isRSA {
		if _, ok := opts.(*rsa.PSSOptions); ok {
			sopts.RSAPadding = RSAPSS
		} else {
			sopts.RSAPadding = RSAPKCS1v15
		}
	}
	return a.inner.SignDigest(digest, sopts)
}

func hashFromCrypto(h crypto.Hash) (Hash, error) {
	switch h {
	case crypto.SHA256:
		return SHA256, nil
	case crypto.SHA384:
		return SHA384, nil
	case crypto.SHA512:
		return SHA512, nil
	default:
		return "", fmt.Errorf("unsupported hash %v", h)
	}
}
