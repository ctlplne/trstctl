// SPDX-License-Identifier: BUSL-1.1

package crypto

// This file is the feature-neutral X.509 seam for subject algorithms the Go
// standard library can structurally parse but does not yet implement. It does
// not name or register any proprietary algorithm. An edition parser verifies
// the request signature, then hands the already-validated public request shape
// back here so all certificate construction and CA signing remain inside the
// AN-3 boundary.

import (
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- SHA-1 only for RFC 5280 4.2.1.2 method-1 Subject Key Identifier derivation (CWE-328)
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

// OpaqueCSR is a structurally parsed PKCS#10 request whose subject algorithm is
// intentionally not interpreted by core. PublicKeyBytes and Signature are
// public values. A caller MUST verify Signature over RawTBS before issuance.
type OpaqueCSR struct {
	Info CSRInfo

	RawTBS                      []byte
	RawSubject                  []byte
	RawSubjectPublicKeyInfo     []byte
	PublicKeyAlgorithmOID       string
	PublicKeyAlgorithmParamsDER []byte
	PublicKeyBytes              []byte
	SignatureAlgorithmOID       string
	SignatureAlgorithmParamsDER []byte
	Signature                   []byte
}

type opaquePublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// InspectOpaqueCSR parses all profile-relevant PKCS#10 fields without claiming
// that the request signature is valid. It exists because x509.CheckSignature
// quite correctly rejects algorithms the Go release does not implement. The
// licensed algorithm implementation must verify RawTBS/Signature before it
// returns this request to the server as recognized.
func InspectOpaqueCSR(der []byte) (OpaqueCSR, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return OpaqueCSR{}, fmt.Errorf("crypto: parse opaque CSR: %w", err)
	}
	var spki opaquePublicKeyInfo
	rest, err := asn1.Unmarshal(csr.RawSubjectPublicKeyInfo, &spki)
	if err != nil {
		return OpaqueCSR{}, fmt.Errorf("crypto: parse opaque CSR SPKI: %w", err)
	}
	if len(rest) != 0 {
		return OpaqueCSR{}, errors.New("crypto: opaque CSR SPKI has trailing data")
	}
	ekus, err := extKeyUsageNamesFromExtensions(csr.Extensions)
	if err != nil {
		return OpaqueCSR{}, err
	}
	sigAI, sig, err := opaqueCSRSignature(csr.Raw)
	if err != nil {
		return OpaqueCSR{}, err
	}
	if len(sig) != len(csr.Signature) {
		return OpaqueCSR{}, errors.New("crypto: opaque CSR signature shape mismatch")
	}
	return OpaqueCSR{
		Info: CSRInfo{
			KeyAlgorithm:   "unknown",
			DNSNames:       append([]string(nil), csr.DNSNames...),
			IPAddresses:    ipStrings(csr.IPAddresses),
			EmailAddresses: append([]string(nil), csr.EmailAddresses...),
			URIs:           uriStrings(csr.URIs),
			CommonName:     csr.Subject.CommonName,
			RequestedEKUs:  ekus,
		},
		RawTBS:                      append([]byte(nil), csr.RawTBSCertificateRequest...),
		RawSubject:                  append([]byte(nil), csr.RawSubject...),
		RawSubjectPublicKeyInfo:     append([]byte(nil), csr.RawSubjectPublicKeyInfo...),
		PublicKeyAlgorithmOID:       spki.Algorithm.Algorithm.String(),
		PublicKeyAlgorithmParamsDER: append([]byte(nil), spki.Algorithm.Parameters.FullBytes...),
		PublicKeyBytes:              append([]byte(nil), spki.PublicKey.RightAlign()...),
		SignatureAlgorithmOID:       sigAI.Algorithm.String(),
		SignatureAlgorithmParamsDER: append([]byte(nil), sigAI.Parameters.FullBytes...),
		Signature:                   sig,
	}, nil
}

// opaqueCSRSignature extracts the PKCS#10 outer AlgorithmIdentifier. The
// standard parser exposes UnknownSignatureAlgorithm for an unknown algorithm,
// so the raw request is decoded here to retain the standardized dotted OID.
func opaqueCSRSignature(raw []byte) (pkix.AlgorithmIdentifier, []byte, error) {
	var outer struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	rest, err := asn1.Unmarshal(raw, &outer)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, nil, fmt.Errorf("crypto: parse opaque CSR signature: %w", err)
	}
	if len(rest) != 0 || len(outer.TBS.FullBytes) == 0 || len(outer.Signature.Bytes) == 0 {
		return pkix.AlgorithmIdentifier{}, nil, errors.New("crypto: opaque CSR signature is malformed")
	}
	return outer.Algorithm, append([]byte(nil), outer.Signature.RightAlign()...), nil
}

// OpaqueLeafRequest contains the public, already-verified request fields needed
// to mint a leaf whose subject key algorithm is not implemented by crypto/x509.
type OpaqueLeafRequest struct {
	Info                    CSRInfo
	RawSubject              []byte
	SubjectPublicKeyInfoDER []byte
	// SignatureOnly rejects encryption/agreement key usages and changes the
	// legacy default to digitalSignature, as required by signature-only keys.
	SignatureOnly bool
}

// MarshalOpaqueSubjectPublicKeyInfo encodes a SubjectPublicKeyInfo with absent
// AlgorithmIdentifier parameters and raw BIT STRING public-key bytes.
func MarshalOpaqueSubjectPublicKeyInfo(algorithmOID string, publicKey []byte) ([]byte, error) {
	oid, err := parseOID(algorithmOID)
	if err != nil {
		return nil, fmt.Errorf("crypto: opaque SPKI algorithm: %w", err)
	}
	if len(publicKey) == 0 {
		return nil, errors.New("crypto: opaque SPKI public key is empty")
	}
	return asn1.Marshal(opaquePublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		PublicKey: asn1.BitString{Bytes: append([]byte(nil), publicKey...), BitLength: len(publicKey) * 8},
	})
}

// MarshalOpaquePKCS8 wraps an algorithm-specific DER private-key value in a
// PKCS#8 PrivateKeyInfo. keyDER is secret material; the caller owns and must wipe
// both it and the returned buffer after delivery to the intended consumer.
func MarshalOpaquePKCS8(algorithmOID string, keyDER []byte) ([]byte, error) {
	oid, err := parseOID(algorithmOID)
	if err != nil {
		return nil, fmt.Errorf("crypto: opaque PKCS#8 algorithm: %w", err)
	}
	if len(keyDER) == 0 {
		return nil, errors.New("crypto: opaque PKCS#8 private key is empty")
	}
	return asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Version: 0, Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		PrivateKey: append([]byte(nil), keyDER...),
	})
}

// SignOpaqueLeafFromVerifiedRequestWithProfile mints an RFC 5280 leaf over an
// opaque SubjectPublicKeyInfo. It uses crypto/x509 to construct the complete
// profile and extensions with a non-signing metadata adapter, replaces only the
// subject SPKI, then signs the final TBSCertificate through DigestSigner. Thus
// the private CA operation still crosses the isolated-signer boundary exactly
// once and the result is verified against the issuing CA before return.
func SignOpaqueLeafFromVerifiedRequestWithProfile(caCertDER []byte, caSigner DigestSigner, req OpaqueLeafRequest, ttl time.Duration, prof LeafProfile) ([]byte, error) {
	issued, err := SignOpaqueLeafFromVerifiedRequestWithValidity(caCertDER, caSigner, req, ttl, prof)
	return issued.DER, err
}

// SignOpaqueLeafFromVerifiedRequestWithValidity returns the exact signing
// validity anchor alongside the verified leaf. The caller must already have
// verified the opaque request's proof of possession.
func SignOpaqueLeafFromVerifiedRequestWithValidity(caCertDER []byte, caSigner DigestSigner, req OpaqueLeafRequest, ttl time.Duration, prof LeafProfile) (IssuedLeaf, error) {
	return signOpaqueLeafWithPreparation(caCertDER, caSigner, req, ttl, prof, nil)
}

// SignOpaqueLeafFromVerifiedRequestWithPreparation preserves the public serial
// and validity anchor across receiver retries. Bind the preparation durably to
// the exact issuer, verified request and profile before signing; use an
// operation-bound signer to retain the signature as well. This constructor
// enforces the same issuer and profile checks as ordinary opaque issuance.
func SignOpaqueLeafFromVerifiedRequestWithPreparation(caCertDER []byte, caSigner DigestSigner, req OpaqueLeafRequest, ttl time.Duration, prof LeafProfile, prepared LeafPreparation) (IssuedLeaf, error) {
	if _, err := prepared.validatedSerial(); err != nil {
		return IssuedLeaf{}, err
	}
	return signOpaqueLeafWithPreparation(caCertDER, caSigner, req, ttl, prof, &prepared)
}

func signOpaqueLeafWithPreparation(caCertDER []byte, caSigner DigestSigner, req OpaqueLeafRequest, ttl time.Duration, prof LeafProfile, prepared *LeafPreparation) (IssuedLeaf, error) {
	if caSigner == nil {
		return IssuedLeaf{}, errors.New("crypto: opaque leaf requires CA signer")
	}
	if len(req.SubjectPublicKeyInfoDER) == 0 {
		return IssuedLeaf{}, errors.New("crypto: opaque leaf requires subject SPKI")
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return IssuedLeaf{}, fmt.Errorf("crypto: parse opaque-leaf CA cert: %w", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if prof.ClampTTLToIssuer {
		remaining := caCert.NotAfter.Sub(now)
		if remaining <= 0 {
			return IssuedLeaf{}, &leafProfileError{fmt.Sprintf("issuing CA expired at %s; it cannot vouch for a new leaf", caCert.NotAfter.UTC().Format(time.RFC3339))}
		}
		if prepared != nil {
			remaining = caCert.NotAfter.Sub(prepared.ValidityAnchor)
			if remaining <= 0 {
				return IssuedLeaf{}, &leafProfileError{"retained leaf validity starts after issuer expiry"}
			}
		}
		if ttl <= 0 || ttl > remaining {
			ttl = remaining
		}
	}
	if err := EnforceLeafProfileInfo(req.Info, ttl, prof); err != nil {
		return IssuedLeaf{}, err
	}
	if req.SignatureOnly {
		if u := prof.AllowedKeyUsages; u != nil && (u.KeyEncipherment || u.KeyAgreement || u.DataEncipherment) {
			return IssuedLeaf{}, &leafProfileError{"signature-only subject key cannot use keyEncipherment, keyAgreement, or dataEncipherment"}
		}
		prof.AllowedKeyUsages = &KeyUsages{DigitalSignature: true}
	}

	var spki opaquePublicKeyInfo
	if rest, err := asn1.Unmarshal(req.SubjectPublicKeyInfoDER, &spki); err != nil || len(rest) != 0 {
		return IssuedLeaf{}, errors.New("crypto: opaque leaf subject SPKI is malformed")
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 || len(spki.PublicKey.Bytes) == 0 || spki.PublicKey.BitLength != len(spki.PublicKey.Bytes)*8 {
		return IssuedLeaf{}, errors.New("crypto: opaque leaf subject SPKI must have absent parameters and an octet-aligned non-empty key")
	}
	// RawContent wins over the decoded fields during asn1.Marshal. Clear it so
	// the validated algorithm/key fields above are what enter the certificate.
	spki.Raw = nil

	var serial *big.Int
	if prepared != nil {
		serial, err = prepared.validatedSerial()
	} else {
		serial, err = randomSerial()
	}
	if err != nil {
		return IssuedLeaf{}, err
	}
	knownEKUs, customEKUs, err := leafExtKeyUsage(prof.AllowedExtKeyUsage)
	if err != nil {
		return IssuedLeaf{}, &leafProfileError{err.Error()}
	}
	ips, err := opaqueIPs(req.Info.IPAddresses)
	if err != nil {
		return IssuedLeaf{}, err
	}
	uniqueURIs, err := opaqueURIs(req.Info.URIs)
	if err != nil {
		return IssuedLeaf{}, err
	}
	ski := sha1.Sum(spki.PublicKey.Bytes) // #nosec G401 -- RFC 5280 4.2.1.2 method-1 SKID: an identifier, not integrity (CWE-328)
	if prepared != nil {
		now = prepared.ValidityAnchor.UTC()
	}
	notBefore, notAfter, err := leafValidityBounds(now, ttl, prof.MaxValidity)
	if err != nil {
		return IssuedLeaf{}, err
	}
	leaf := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.Info.CommonName},
		DNSNames:     append([]string(nil), req.Info.DNSNames...), IPAddresses: ips,
		EmailAddresses: append([]string(nil), req.Info.EmailAddresses...), URIs: uniqueURIs,
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: leafKeyUsageForProfile(prof), ExtKeyUsage: knownEKUs, UnknownExtKeyUsage: customEKUs,
		BasicConstraintsValid: true, SubjectKeyId: ski[:],
		CRLDistributionPoints: append([]string(nil), prof.CRLDistributionPoints...),
		OCSPServer:            append([]string(nil), prof.OCSPServers...), IssuingCertificateURL: append([]string(nil), prof.IssuingCertificateURL...),
	}
	if len(caCert.SubjectKeyId) > 0 {
		leaf.AuthorityKeyId = append([]byte(nil), caCert.SubjectKeyId...)
	}
	if len(prof.ExtraExtensions) > 0 {
		extra, err := x509Extensions(prof.ExtraExtensions)
		if err != nil {
			return IssuedLeaf{}, err
		}
		leaf.ExtraExtensions = append(leaf.ExtraExtensions, extra...)
	}
	if len(prof.CertificatePolicyOIDs) > 0 {
		leaf.PolicyIdentifiers, err = policyOIDs(prof.CertificatePolicyOIDs)
		if err != nil {
			return IssuedLeaf{}, err
		}
		leaf.Policies, err = modernPolicyOIDs(prof.CertificatePolicyOIDs)
		if err != nil {
			return IssuedLeaf{}, err
		}
	}

	metadataKey, err := GenerateLockedKey(caSigner.Algorithm())
	if err != nil {
		return IssuedLeaf{}, err
	}
	defer metadataKey.Destroy()
	metadataAdapter, err := newX509Signer(metadataKey)
	if err != nil {
		return IssuedLeaf{}, err
	}
	metadataParent := *caCert
	metadataParent.PublicKey = metadataAdapter.Public()
	// x509.CreateCertificate is used only as the canonical RFC 5280 extension
	// encoder. Its throwaway locked key has the same algorithm as the real CA,
	// while the actual CA signer is invoked exactly once for the final TBS.
	metadataDER, err := x509.CreateCertificate(rand.Reader, leaf, &metadataParent, metadataAdapter.Public(), metadataAdapter)
	if err != nil {
		return IssuedLeaf{}, fmt.Errorf("crypto: build opaque leaf metadata: %w", err)
	}
	var cert opaqueCertificate
	if rest, err := asn1.Unmarshal(metadataDER, &cert); err != nil || len(rest) != 0 {
		return IssuedLeaf{}, errors.New("crypto: decode opaque leaf metadata certificate")
	}
	if len(req.RawSubject) > 0 {
		var subject pkix.RDNSequence
		if rest, err := asn1.Unmarshal(req.RawSubject, &subject); err != nil || len(rest) != 0 {
			return IssuedLeaf{}, errors.New("crypto: opaque leaf subject is malformed")
		}
		cert.TBS.Subject = asn1.RawValue{FullBytes: append([]byte(nil), req.RawSubject...)}
	}
	cert.TBS.PublicKey = spki
	cert.TBS.Raw = nil
	tbsDER, err := asn1.Marshal(cert.TBS)
	if err != nil {
		return IssuedLeaf{}, fmt.Errorf("crypto: marshal opaque TBSCertificate: %w", err)
	}
	cert.TBS.Raw = tbsDER
	signature, err := signOpaqueTBS(caSigner, tbsDER)
	if err != nil {
		return IssuedLeaf{}, err
	}
	cert.SignatureValue = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	der, err := asn1.Marshal(cert)
	if err != nil {
		return IssuedLeaf{}, fmt.Errorf("crypto: marshal opaque certificate: %w", err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return IssuedLeaf{}, fmt.Errorf("crypto: parse issued opaque leaf: %w", err)
	}
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		return IssuedLeaf{}, fmt.Errorf("crypto: issued opaque leaf failed verification (signer misbehaved): %w", err)
	}
	return IssuedLeaf{DER: der, ValidityAnchor: now}, nil
}

type opaqueCertificate struct {
	TBS                opaqueTBSCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type opaqueTBSCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *bigIntAlias
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           opaqueValidity
	Subject            asn1.RawValue
	PublicKey          opaquePublicKeyInfo
	UniqueID           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

// bigIntAlias lets the local ASN.1 mirror use the exact *big.Int wire shape
// without exporting that implementation detail in OpaqueLeafRequest.
type bigIntAlias = big.Int

type opaqueValidity struct {
	NotBefore, NotAfter time.Time
}

func signOpaqueTBS(signer DigestSigner, tbs []byte) ([]byte, error) {
	var h Hash
	switch signer.Algorithm() {
	case RSA2048, RSA3072, RSA4096, ECDSAP256:
		h = SHA256
	case ECDSAP384:
		h = SHA384
	case ECDSAP521:
		h = SHA512
	default:
		return nil, fmt.Errorf("crypto: opaque leaf CA algorithm %s is unsupported", signer.Algorithm())
	}
	digest, err := Digest(h, tbs)
	if err != nil {
		return nil, err
	}
	return signer.SignDigest(digest, SignOptions{Hash: h})
}

func opaqueIPs(raw []string) ([]net.IP, error) {
	out := make([]net.IP, 0, len(raw))
	for _, s := range raw {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("crypto: opaque leaf IP SAN %q is invalid", s)
		}
		out = append(out, ip)
	}
	return out, nil
}

func opaqueURIs(raw []string) ([]*url.URL, error) {
	out := make([]*url.URL, 0, len(raw))
	for _, s := range raw {
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" {
			return nil, fmt.Errorf("crypto: opaque leaf URI SAN %q is invalid", s)
		}
		out = append(out, u)
	}
	return out, nil
}
