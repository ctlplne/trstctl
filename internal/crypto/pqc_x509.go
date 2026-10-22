// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/sha1" // #nosec G505 -- RFC 5280 4.2.1.2 method-1 key identifiers only (CWE-328)
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// ML-DSA in X.509 (RFC 9881, A26/A27 card P10). One OID names both the key
// and the signature, the AlgorithmIdentifier carries no parameters, and the
// signature is the pure FIPS 204 signature over the complete TBS bytes: there
// is no pre-hash, so the issuing key's holder (the isolated signer) must see
// the whole TBS. Go's x509 cannot sign or verify these, so every builder here
// lets x509 encode the certificate, CRL or OCSP body with a throwaway
// classical key as the canonical RFC 5280 encoder, then swaps in the ML-DSA
// algorithm (and, for an ML-DSA subject, its SubjectPublicKeyInfo), re-encodes
// the TBS and signs exactly those bytes through the DigestSigner with HashNone.
// Verification goes through the CIRCL schemes over the same raw TBS.

var mldsaX509OIDs = map[Algorithm]asn1.ObjectIdentifier{
	Algorithm("ML-DSA-44"): {2, 16, 840, 1, 101, 3, 4, 3, 17},
	Algorithm("ML-DSA-65"): {2, 16, 840, 1, 101, 3, 4, 3, 18},
	Algorithm("ML-DSA-87"): {2, 16, 840, 1, 101, 3, 4, 3, 19},
}

func mldsaScheme(alg Algorithm) (sign.Scheme, bool) {
	switch alg {
	case Algorithm("ML-DSA-44"):
		return mldsa44.Scheme(), true
	case Algorithm("ML-DSA-65"):
		return mldsa65.Scheme(), true
	case Algorithm("ML-DSA-87"):
		return mldsa87.Scheme(), true
	default:
		return nil, false
	}
}

// MLDSAX509Algorithm names the ML-DSA parameter set an RFC 9881 OID denotes.
func MLDSAX509Algorithm(oid asn1.ObjectIdentifier) (Algorithm, bool) {
	for alg, known := range mldsaX509OIDs {
		if known.Equal(oid) {
			return alg, true
		}
	}
	return "", false
}

// PureX509Algorithm reports whether alg signs X.509 objects as a pure message
// signature (ML-DSA), and its RFC 9881 OID.
func PureX509Algorithm(alg Algorithm) (asn1.ObjectIdentifier, bool) {
	oid, ok := mldsaX509OIDs[alg]
	return oid, ok
}

// pureX509Signer reports whether signer holds an ML-DSA key.
func pureX509Signer(signer DigestSigner) (asn1.ObjectIdentifier, bool) {
	if signer == nil {
		return nil, false
	}
	return PureX509Algorithm(signer.Algorithm())
}

func pureAlgorithmIdentifier(oid asn1.ObjectIdentifier) pkix.AlgorithmIdentifier {
	// Parameters stay absent (RFC 9881 §2): the zero RawValue is omitted.
	return pkix.AlgorithmIdentifier{Algorithm: oid}
}

// PureSubjectPublicKeyInfo encodes an ML-DSA public key (its FIPS 204 bytes)
// as the RFC 9881 SubjectPublicKeyInfo.
func PureSubjectPublicKeyInfo(pub PublicKey) ([]byte, error) {
	oid, ok := PureX509Algorithm(pub.Algorithm)
	if !ok {
		return nil, fmt.Errorf("crypto: %s is not an X.509 pure signature algorithm", pub.Algorithm)
	}
	scheme, _ := mldsaScheme(pub.Algorithm)
	if len(pub.DER) != scheme.PublicKeySize() {
		return nil, fmt.Errorf("crypto: %s public key is %d bytes, want %d", pub.Algorithm, len(pub.DER), scheme.PublicKeySize())
	}
	return MarshalOpaqueSubjectPublicKeyInfo(oid.String(), pub.DER)
}

// pureSubjectKeyID is the RFC 5280 4.2.1.2 method-1 identifier of an ML-DSA
// public key: SHA-1 of the subjectPublicKey bits, as for every other key here.
func pureSubjectKeyID(pub PublicKey) []byte {
	sum := sha1.Sum(pub.DER) // #nosec G401 -- key identifier, not integrity (CWE-328)
	return sum[:]
}

// VerifyPureSignature verifies a pure ML-DSA signature over the whole message
// (empty context), the form RFC 9881 certificates, CRLs and OCSP responses use.
func VerifyPureSignature(pub PublicKey, message, signature []byte) error {
	scheme, ok := mldsaScheme(pub.Algorithm)
	if !ok {
		return fmt.Errorf("crypto: %s is not an X.509 pure signature algorithm", pub.Algorithm)
	}
	key, err := scheme.UnmarshalBinaryPublicKey(pub.DER)
	if err != nil {
		return fmt.Errorf("crypto: parse %s public key: %w", pub.Algorithm, err)
	}
	if !scheme.Verify(key, message, signature, nil) {
		return errors.New("crypto: ML-DSA signature verification failed")
	}
	return nil
}

// purePublicKeyOfCertificate returns the certificate's ML-DSA public key when
// its SubjectPublicKeyInfo names one.
func purePublicKeyOfCertificate(cert *x509.Certificate) (PublicKey, bool, error) {
	if cert == nil || cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return PublicKey{}, false, nil
	}
	var spki opaquePublicKeyInfo
	if rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil || len(rest) != 0 {
		return PublicKey{}, false, errors.New("crypto: malformed SubjectPublicKeyInfo")
	}
	alg, ok := MLDSAX509Algorithm(spki.Algorithm.Algorithm)
	if !ok {
		return PublicKey{}, false, nil
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 || spki.PublicKey.BitLength != len(spki.PublicKey.Bytes)*8 {
		return PublicKey{}, false, fmt.Errorf("crypto: %s SubjectPublicKeyInfo must have absent parameters and an octet-aligned key", alg)
	}
	return PublicKey{Algorithm: alg, DER: append([]byte(nil), spki.PublicKey.Bytes...)}, true, nil
}

// signedObject is the outer SIGNED{} shape shared by Certificate and
// CertificateList: the TBS, the signature algorithm and the signature.
type signedObject struct {
	TBS                asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// VerifyCertificateIssuedBy checks child's signature against issuer, through
// the CIRCL scheme when the issuer holds an ML-DSA key and through Go x509
// otherwise. It replaces CheckSignatureFrom wherever a post-quantum issuer can
// appear; it does not check validity, constraints or key usage.
func VerifyCertificateIssuedBy(child, issuer *x509.Certificate) error {
	if child == nil || issuer == nil {
		return errors.New("crypto: certificate and issuer are required")
	}
	pub, pure, err := purePublicKeyOfCertificate(issuer)
	if err != nil {
		return err
	}
	if !pure {
		return child.CheckSignatureFrom(issuer)
	}
	var outer signedObject
	if rest, err := asn1.Unmarshal(child.Raw, &outer); err != nil || len(rest) != 0 {
		return errors.New("crypto: malformed certificate")
	}
	return verifyPureSigned(pub, outer, child.RawTBSCertificate, child.Signature)
}

func verifyPureSigned(pub PublicKey, outer signedObject, tbs, signature []byte) error {
	oid, _ := PureX509Algorithm(pub.Algorithm)
	if !outer.SignatureAlgorithm.Algorithm.Equal(oid) || len(outer.SignatureAlgorithm.Parameters.FullBytes) != 0 {
		return fmt.Errorf("crypto: signature algorithm is not %s with absent parameters", pub.Algorithm)
	}
	return VerifyPureSignature(pub, tbs, signature)
}

// completeOpaqueCertificate finishes a certificate whose RFC 5280 body x509
// encoded with throwaway material: it installs subjectSPKI when the real
// subject key is one x509 cannot carry (nil keeps the encoded key), names the
// issuer's ML-DSA algorithm when the signer is post-quantum, re-encodes the
// TBS and signs exactly those bytes through signer. The result is parsed back
// and verified against the signer's own public key before it is returned.
func completeOpaqueCertificate(signer DigestSigner, metadataDER, subjectSPKI []byte) ([]byte, error) {
	var cert opaqueCertificate
	if rest, err := asn1.Unmarshal(metadataDER, &cert); err != nil || len(rest) != 0 {
		return nil, errors.New("crypto: decode certificate metadata")
	}
	if len(subjectSPKI) != 0 {
		var spki opaquePublicKeyInfo
		if rest, err := asn1.Unmarshal(subjectSPKI, &spki); err != nil || len(rest) != 0 {
			return nil, errors.New("crypto: subject SubjectPublicKeyInfo is malformed")
		}
		spki.Raw = nil
		cert.TBS.PublicKey = spki
	}
	if oid, pure := pureX509Signer(signer); pure {
		cert.TBS.SignatureAlgorithm = pureAlgorithmIdentifier(oid)
		cert.SignatureAlgorithm = pureAlgorithmIdentifier(oid)
	}
	cert.TBS.Raw = nil
	tbsDER, err := asn1.Marshal(cert.TBS)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal TBSCertificate: %w", err)
	}
	cert.TBS.Raw = tbsDER
	signature, err := signOpaqueTBS(signer, tbsDER)
	if err != nil {
		return nil, err
	}
	cert.SignatureValue = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	der, err := asn1.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal certificate: %w", err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse issued certificate: %w", err)
	}
	if _, pure := pureX509Signer(signer); pure {
		if err := VerifyPureSignature(signer.Public(), issued.RawTBSCertificate, issued.Signature); err != nil {
			return nil, fmt.Errorf("crypto: issued certificate failed verification (signer misbehaved): %w", err)
		}
	}
	return der, nil
}

// metadataSigner is the throwaway classical key x509 encodes with when the
// real signer is post-quantum; its algorithm is what x509 can carry.
func metadataSigner(signer DigestSigner) (*LockedSigner, *x509Signer, error) {
	alg := ECDSAP256
	if _, pure := pureX509Signer(signer); !pure {
		alg = signer.Algorithm()
	}
	key, err := GenerateLockedKey(alg)
	if err != nil {
		return nil, nil, err
	}
	adapter, err := newX509Signer(key)
	if err != nil {
		key.Destroy()
		return nil, nil, err
	}
	return key, adapter, nil
}

// resignPureSigned re-signs an x509-encoded SIGNED{} object (a CRL) with an
// ML-DSA signer: the TBS's own signature AlgorithmIdentifier (the first
// SEQUENCE element of TBSCertList) and the outer one both become the ML-DSA
// identifier, and the signature covers the re-encoded TBS.
func resignPureSigned(signer DigestSigner, der []byte) ([]byte, error) {
	oid, pure := pureX509Signer(signer)
	if !pure {
		return nil, errors.New("crypto: pure re-signing needs an ML-DSA signer")
	}
	var outer signedObject
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) != 0 {
		return nil, errors.New("crypto: decode signed object")
	}
	algID, err := asn1.Marshal(pureAlgorithmIdentifier(oid))
	if err != nil {
		return nil, err
	}
	var body []byte
	replaced := false
	for rest := outer.TBS.Bytes; len(rest) > 0; {
		var element asn1.RawValue
		next, err := asn1.Unmarshal(rest, &element)
		if err != nil {
			return nil, fmt.Errorf("crypto: walk TBS: %w", err)
		}
		if !replaced && element.Class == asn1.ClassUniversal && element.Tag == asn1.TagSequence {
			element.FullBytes = algID
			replaced = true
		}
		body = append(body, element.FullBytes...)
		rest = next
	}
	if !replaced {
		return nil, errors.New("crypto: TBS carries no signature AlgorithmIdentifier")
	}
	tbs, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		return nil, err
	}
	signature, err := signer.SignDigest(tbs, SignOptions{Hash: HashNone})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(signedObject{
		TBS:                asn1.RawValue{FullBytes: tbs},
		SignatureAlgorithm: pureAlgorithmIdentifier(oid),
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// OCSP BasicOCSPResponse mirrors (RFC 6960 §4.2.1), with the response data
// kept raw so an ML-DSA signature can replace the throwaway one.
type ocspResponseASN1 struct {
	Status   asn1.Enumerated
	Response ocspResponseBytes `asn1:"explicit,tag:0,optional"`
}

type ocspResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspBasicResponse struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// resignPureOCSPResponse replaces a throwaway classical signature on an OCSP
// response with the issuing CA's ML-DSA signature over the same response data.
func resignPureOCSPResponse(signer DigestSigner, der []byte) ([]byte, error) {
	oid, pure := pureX509Signer(signer)
	if !pure {
		return nil, errors.New("crypto: pure OCSP signing needs an ML-DSA signer")
	}
	var outer ocspResponseASN1
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) != 0 {
		return nil, errors.New("crypto: decode OCSP response")
	}
	var basic ocspBasicResponse
	if rest, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil || len(rest) != 0 {
		return nil, errors.New("crypto: decode basic OCSP response")
	}
	signature, err := signer.SignDigest(basic.TBSResponseData.FullBytes, SignOptions{Hash: HashNone})
	if err != nil {
		return nil, err
	}
	basic.SignatureAlgorithm = pureAlgorithmIdentifier(oid)
	basic.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	basicDER, err := asn1.Marshal(basic)
	if err != nil {
		return nil, err
	}
	outer.Response.Response = basicDER
	return asn1.Marshal(outer)
}
