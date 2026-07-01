package crypto

// RFC 3161 time-stamp token (CMS) encoding, kept inside the AN-3 boundary so the
// TSA service (internal/tsa) never touches crypto/x509 or ASN.1 directly. A
// time-stamp token is a CMS SignedData (RFC 5652) whose encapsulated content is a
// DER-encoded TSTInfo with eContentType = id-ct-TSTInfo — exactly what a stock
// verifier (`openssl ts -verify`, a DSS/ESS validator) parses. Previously the TSA
// emitted a JSON manifest that no RFC 3161 verifier could read (INTEROP-005); this
// produces the real wire format.
//
// The token's SignerInfo carries the mandatory signed attributes (contentType,
// messageDigest over the TSTInfo) plus signingTime and ESS SigningCertificate
// attributes (RFC 3161 / RFC 5035), and the signature is computed over the DER of
// the SignedAttributes (re-tagged SET OF) per RFC 5652 §5.4 — so the signature is
// verifiable by any CMS implementation, not just our own parser (non-circular).

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	// id-ct-TSTInfo: the eContentType of an RFC 3161 token.
	oidCTTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	// CMS signed-attribute OIDs (RFC 5652 §11).
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	// id-aa-signingCertificate (RFC 2634 / RFC 3161) binds the token to the
	// TSA cert for older RFC 3161 verifiers. SHA-1 is the legacy ESS certificate
	// identifier here, not a signature or content digest.
	oidAttrSigningCert = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	// id-aa-signingCertificateV2 (RFC 5035) — binds the token to the TSA cert.
	oidAttrSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidDigestSHA256      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// TSTInfoParams describes the TSTInfo to encode into a token.
type TSTInfoParams struct {
	PolicyOID     string // dotted TSA policy OID
	HashedMessage []byte // the message imprint (a SHA-256 digest)
	SerialNumber  uint64
	GenTime       time.Time
	Nonce         *big.Int // optional client nonce copied from TimeStampReq
}

// asn1MessageImprint is MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }.
type asn1MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// asn1TSTInfo is the subset of TSTInfo we populate (version, policy,
// messageImprint, serialNumber, genTime). Optional fields (accuracy, ordering,
// nonce, tsa, extensions) are omitted, which is RFC 3161-conformant.
type asn1TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint asn1MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Nonce          *big.Int  `asn1:"optional"`
}

// EncodeTSTInfo returns the DER of a TSTInfo for the given parameters. This is the
// eContent of the time-stamp token and the bytes the messageDigest attribute
// covers.
func EncodeTSTInfo(p TSTInfoParams) ([]byte, error) {
	if len(p.HashedMessage) == 0 {
		return nil, errors.New("crypto: TSTInfo requires a message imprint")
	}
	policy, err := parseOID(p.PolicyOID)
	if err != nil {
		return nil, fmt.Errorf("crypto: TSA policy oid: %w", err)
	}
	info := asn1TSTInfo{
		Version: 1,
		Policy:  policy,
		MessageImprint: asn1MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256},
			HashedMessage: append([]byte(nil), p.HashedMessage...),
		},
		SerialNumber: new(big.Int).SetUint64(p.SerialNumber),
		GenTime:      p.GenTime.UTC(),
	}
	if p.Nonce != nil {
		info.Nonce = new(big.Int).Set(p.Nonce)
	}
	return asn1.Marshal(info)
}

// --- CMS SignedData over the TSTInfo -----------------------------------------

type tsaEncapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	// EContent is the [0] EXPLICIT { OCTET STRING } construct, pre-built as a
	// context-specific compound RawValue. asn1.Marshal does NOT apply an
	// `explicit,tag:0` struct tag to a RawValue field (it emits the RawValue by its
	// own Class/Tag), so the [0] wrapper is constructed in BuildTimeStampToken and
	// carried here verbatim.
	EContent asn1.RawValue `asn1:"optional"`
}

type tsaIssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type tsaAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue // SET OF AttributeValue
}

type tsaSignerInfo struct {
	Version            int
	SID                tsaIssuerAndSerial
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type tsaSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue // SET OF AlgorithmIdentifier
	EncapContentInfo tsaEncapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      asn1.RawValue // SET OF SignerInfo
}

type tsaContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     tsaSignedData `asn1:"explicit,tag:0"`
}

// essCertID is ESSCertID ::= SEQUENCE { certHash OCTET STRING, ... }. RFC 3161
// original verifiers bind the token to the TSA certificate through this SHA-1
// identifier. We carry only certHash, the interoperable subset.
type essCertID struct {
	CertHash []byte
}

type signingCertificate struct {
	Certs []essCertID
}

// essCertIDv2 is ESSCertIDv2 ::= SEQUENCE { hashAlgorithm (default SHA-256, so
// omitted), certHash OCTET STRING, ... }. We carry only certHash (SHA-256 of the
// TSA cert), which is the common interop subset.
type essCertIDv2 struct {
	CertHash []byte
}

type signingCertificateV2 struct {
	Certs []essCertIDv2
}

// BuildTimeStampToken assembles an RFC 3161 time-stamp token: a CMS SignedData
// over tstInfoDER (eContentType id-ct-TSTInfo), signed by tsaSigner whose
// certificate is tsaCertDER. The SignerInfo carries contentType, messageDigest,
// signingTime, and ESS signingCertificate/signingCertificateV2 signed attributes.
// The signature is over the DER of the SignedAttributes (SET OF) per RFC 5652, so
// a stock CMS verifier validates it. Returns the DER token
// (application/timestamp-reply payload, minus the PKIStatus wrapper the TSA service
// adds for a full response).
func BuildTimeStampToken(tstInfoDER []byte, tsaCertDER []byte, tsaSigner DigestSigner) ([]byte, error) {
	tsaCert, err := x509.ParseCertificate(tsaCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse TSA cert: %w", err)
	}

	// messageDigest = SHA-256 over the eContent (the DER TSTInfo).
	mdSum := sha256.Sum256(tstInfoDER)

	// ESS signingCertificate: SHA-1 over the TSA certificate for RFC 3161-era
	// verifiers, plus signingCertificateV2: SHA-256 over the same certificate for
	// modern RFC 5035 verifiers.
	certSumV1 := sha1.Sum(tsaCertDER)
	scDER, err := asn1.Marshal(signingCertificate{Certs: []essCertID{{CertHash: certSumV1[:]}}})
	if err != nil {
		return nil, fmt.Errorf("crypto: encode signingCertificate: %w", err)
	}
	certSum := sha256.Sum256(tsaCertDER)
	scv2DER, err := asn1.Marshal(signingCertificateV2{Certs: []essCertIDv2{{CertHash: certSum[:]}}})
	if err != nil {
		return nil, fmt.Errorf("crypto: encode signingCertificateV2: %w", err)
	}

	signedAttrs, err := buildSignedAttrs(mdSum[:], scDER, scv2DER)
	if err != nil {
		return nil, err
	}

	// The signature is computed over the DER encoding of the SignedAttributes as an
	// explicit SET OF (tag 0x31), NOT the [0] IMPLICIT form that appears in the
	// message (RFC 5652 §5.4).
	signedAttrsForSig := reTagToSetOf(signedAttrs)
	sig, err := SignMessage(tsaSigner, signedAttrsForSig)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign TSTInfo: %w", err)
	}
	sigAlg, err := signatureAlgFor(tsaSigner)
	if err != nil {
		return nil, err
	}

	issuerRaw := asn1.RawValue{FullBytes: tsaCert.RawIssuer}
	si := tsaSignerInfo{
		Version:            1,
		SID:                tsaIssuerAndSerial{IssuerName: issuerRaw, SerialNumber: tsaCert.SerialNumber},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256},
		SignedAttrs:        asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signedAttrs},
		SignatureAlgorithm: sigAlg,
		Signature:          sig,
	}
	siDER, err := asn1.Marshal(si)
	if err != nil {
		return nil, fmt.Errorf("crypto: encode SignerInfo: %w", err)
	}

	// DigestAlgorithms is a SET OF AlgorithmIdentifier (CMS), so wrap the single
	// AlgorithmIdentifier DER in a universal SET (tag 0x31), not the SEQUENCE OF
	// (0x30) asn1.Marshal of a slice would produce.
	oneAlgDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256})
	if err != nil {
		return nil, err
	}

	// EncapContentInfo: eContentType id-ct-TSTInfo, eContent [0] EXPLICIT OCTET
	// STRING. Build the OCTET STRING DER, then wrap it in a [0] EXPLICIT context tag
	// manually (asn1.Marshal ignores an `explicit` struct tag on a RawValue field).
	octetDER, err := asn1.Marshal(tstInfoDER) // OCTET STRING { tstInfoDER }
	if err != nil {
		return nil, err
	}
	eContent := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: octetDER}

	sd := tsaSignedData{
		Version:          3,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: oneAlgDER},
		EncapContentInfo: tsaEncapContentInfo{
			EContentType: oidCTTSTInfo,
			EContent:     eContent,
		},
		Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: tsaCertDER},
		SignerInfos:  asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: siDER},
	}
	ci := tsaContentInfo{ContentType: oidSignedData, Content: sd}
	return asn1.Marshal(ci)
}

// buildSignedAttrs assembles the SignedAttributes (as the [0] IMPLICIT body bytes,
// i.e. the concatenated DER of each Attribute) for a TSTInfo: contentType
// (id-ct-TSTInfo), messageDigest, signingTime, and ESS signingCertificate/
// signingCertificateV2.
func buildSignedAttrs(messageDigest, signingCertDER, signingCertV2DER []byte) ([]byte, error) {
	contentTypeVal, err := marshalAttrValues(oidCTTSTInfo)
	if err != nil {
		return nil, err
	}
	mdVal, err := marshalAttrValues(messageDigest)
	if err != nil {
		return nil, err
	}
	stVal, err := marshalAttrValuesRaw(asn1.RawValue{FullBytes: mustMarshalUTCTime()})
	if err != nil {
		return nil, err
	}
	scVal, err := marshalAttrValuesRaw(asn1.RawValue{FullBytes: signingCertDER})
	if err != nil {
		return nil, err
	}
	scv2Val, err := marshalAttrValuesRaw(asn1.RawValue{FullBytes: signingCertV2DER})
	if err != nil {
		return nil, err
	}
	attrs := []tsaAttribute{
		{Type: oidAttrContentType, Values: contentTypeVal},
		{Type: oidAttrMessageDigest, Values: mdVal},
		{Type: oidAttrSigningTime, Values: stVal},
		{Type: oidAttrSigningCert, Values: scVal},
		{Type: oidAttrSigningCertV2, Values: scv2Val},
	}
	// DER SET OF requires the elements be sorted by their encoding (X.690 §11.6).
	// A CMS verifier (openssl, smallstep/pkcs7) reconstructs the SignedAttributes
	// as a SET OF and re-sorts before hashing, so the [0] IMPLICIT body we emit AND
	// the SET OF we sign must both be in this sorted order — otherwise the verifier's
	// digest over the attributes differs from ours and the signature is rejected.
	encoded := make([][]byte, 0, len(attrs))
	for _, a := range attrs {
		der, err := asn1.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("crypto: encode signed attribute %v: %w", a.Type, err)
		}
		encoded = append(encoded, der)
	}
	sortDERSet(encoded)
	var body []byte
	for _, der := range encoded {
		body = append(body, der...)
	}
	return body, nil
}

// sortDERSet sorts DER element encodings for a SET OF per X.690 §11.6: shorter
// encodings sort first when one is a prefix of the other, else lexicographic byte
// order.
func sortDERSet(elems [][]byte) {
	for i := 0; i < len(elems); i++ {
		for j := i + 1; j < len(elems); j++ {
			if derLess(elems[j], elems[i]) {
				elems[i], elems[j] = elems[j], elems[i]
			}
		}
	}
}

func derLess(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// mustMarshalUTCTime encodes the current time as an ASN.1 UTCTime value for the
// signingTime attribute.
func mustMarshalUTCTime() []byte {
	der, _ := asn1.Marshal(time.Now().UTC())
	return der
}

// marshalAttrValues wraps a single value in a SET OF (the Attribute.values field).
func marshalAttrValues(v any) (asn1.RawValue, error) {
	der, err := asn1.Marshal(v)
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: der}, nil
}

// marshalAttrValuesRaw wraps a pre-encoded value in a SET OF.
func marshalAttrValuesRaw(v asn1.RawValue) (asn1.RawValue, error) {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: v.FullBytes}, nil
}

// reTagToSetOf returns the DER of a universal SET OF whose contents are body (the
// concatenated Attribute DERs). RFC 5652 §5.4: the signature input is the
// SignedAttributes encoded as an explicit SET OF, regardless of the [0] IMPLICIT
// tag used in the message.
func reTagToSetOf(body []byte) []byte {
	setVal := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: body}
	der, _ := asn1.Marshal(setVal)
	return der
}

func signatureAlgFor(s DigestSigner) (pkix.AlgorithmIdentifier, error) {
	switch s.Algorithm() {
	case RSA2048, RSA3072, RSA4096:
		return pkix.AlgorithmIdentifier{Algorithm: oidSigRSASHA256}, nil
	case ECDSAP256, ECDSAP384, ECDSAP521:
		return pkix.AlgorithmIdentifier{Algorithm: oidSigECDSASHA256}, nil
	default:
		return pkix.AlgorithmIdentifier{}, fmt.Errorf("crypto: unsupported TSA signer algorithm %q", s.Algorithm())
	}
}
