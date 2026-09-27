// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- RFC 5816 ESSCertIDv1 certificate identifier, not a signature digest (CWE-328)
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// VerifyTimeStampToken authenticates a present RFC 3161 CMS artifact and binds
// its signed content to the independently authenticated manifest. The caller
// must first verify the expected TSA certificate's trust chain and timestamping
// profile. This function requires that exact certificate to be the sole CMS
// signer; it does not establish revocation status or long-term validity.
func VerifyTimeStampToken(der, tsaCertDER []byte, expected TSTInfoParams) error {
	var envelope tsaContentInfo
	rest, err := asn1.Unmarshal(der, &envelope)
	if err != nil || len(rest) != 0 {
		return errors.New("crypto: timestamp is not a complete DER CMS container")
	}
	// Do not let the dependency's BER decoder discard trailing or unrecognized
	// container fields. Raw certificate/content/signer bytes remain unchanged.
	encoded, err := asn1.Marshal(envelope)
	if err != nil || !bytes.Equal(encoded, der) {
		return errors.New("crypto: timestamp CMS container has unsupported or noncanonical fields")
	}
	if !envelope.ContentType.Equal(oidSignedData) || envelope.Content.Version != 3 ||
		!envelope.Content.EncapContentInfo.EContentType.Equal(oidCTTSTInfo) {
		return errors.New("crypto: timestamp CMS must encapsulate TSTInfo SignedData")
	}
	algorithms := envelope.Content.DigestAlgorithms
	var digestAlgorithm pkix.AlgorithmIdentifier
	if algorithms.Class != asn1.ClassUniversal || algorithms.Tag != asn1.TagSet || !algorithms.IsCompound {
		return errors.New("crypto: timestamp CMS has no digest algorithm set")
	}
	if rest, err := asn1.Unmarshal(algorithms.Bytes, &digestAlgorithm); err != nil || len(rest) != 0 || !timestampSHA256Algorithm(digestAlgorithm) {
		return errors.New("crypto: timestamp CMS must declare one SHA-256 digest algorithm")
	}
	contentWrapper := envelope.Content.EncapContentInfo.EContent
	if contentWrapper.Class != asn1.ClassContextSpecific || contentWrapper.Tag != 0 || !contentWrapper.IsCompound {
		return errors.New("crypto: timestamp CMS is missing its encapsulated content")
	}
	var content []byte
	if rest, err := asn1.Unmarshal(contentWrapper.Bytes, &content); err != nil || len(rest) != 0 {
		return errors.New("crypto: timestamp CMS content is not one DER octet string")
	}
	p7, err := safeParsePKCS7(der)
	if err != nil {
		return fmt.Errorf("crypto: parse timestamp CMS: %w", err)
	}
	if len(p7.Signers) != 1 {
		return errors.New("crypto: timestamp CMS must have exactly one signer")
	}
	signer := p7.GetOnlySigner()
	if signer == nil || !bytes.Equal(signer.Raw, tsaCertDER) {
		return errors.New("crypto: timestamp CMS signer does not match the verified TSA certificate")
	}
	if !bytes.Equal(p7.Content, content) || p7.Signers[0].Version != 1 || !timestampSHA256Algorithm(p7.Signers[0].DigestAlgorithm) {
		return errors.New("crypto: timestamp CMS content or digest algorithm is inconsistent")
	}
	attributes := make(map[string]asn1.RawValue)
	for _, attribute := range p7.Signers[0].AuthenticatedAttributes {
		name := attribute.Type.String()
		if _, exists := attributes[name]; exists {
			return errors.New("crypto: timestamp CMS has duplicate signed attributes")
		}
		attributes[name] = attribute.Value
	}
	decodeAttribute := func(oid asn1.ObjectIdentifier, value any) error {
		raw, exists := attributes[oid.String()]
		if !exists || raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSet || !raw.IsCompound {
			return errors.New("crypto: timestamp CMS is missing a required signed attribute")
		}
		if rest, err := asn1.Unmarshal(raw.Bytes, value); err != nil || len(rest) != 0 {
			return errors.New("crypto: timestamp CMS signed attribute must contain one value")
		}
		return nil
	}
	var contentType asn1.ObjectIdentifier
	if err := decodeAttribute(oidAttrContentType, &contentType); err != nil {
		return err
	}
	if !contentType.Equal(oidCTTSTInfo) {
		return errors.New("crypto: timestamp CMS signed content type is not TSTInfo")
	}
	var digest []byte
	if err := decodeAttribute(oidAttrMessageDigest, &digest); err != nil {
		return err
	}
	contentDigest := sha256.Sum256(content)
	if !bytes.Equal(digest, contentDigest[:]) {
		return errors.New("crypto: timestamp CMS signed digest does not match its content")
	}
	// Both ESS variants, when present, must identify the exact signer. At least
	// one is required by RFC 3161 / RFC 5816. SHA-1 here identifies a certificate;
	// the content digest and CMS signature remain SHA-256.
	_, v1 := attributes[oidAttrSigningCert.String()]
	_, v2 := attributes[oidAttrSigningCertV2.String()]
	if !v1 && !v2 {
		return errors.New("crypto: timestamp CMS has no signed TSA certificate identifier")
	}
	if v1 {
		var cert signingCertificate
		if err := decodeAttribute(oidAttrSigningCert, &cert); err != nil {
			return err
		}
		sum := sha1.Sum(tsaCertDER) // #nosec G401 -- RFC 5816 ESSCertIDv1 certificate identifier, not a signature digest (CWE-328)
		if len(cert.Certs) == 0 || !bytes.Equal(cert.Certs[0].CertHash, sum[:]) {
			return errors.New("crypto: timestamp CMS ESS certificate identifier does not match its signer")
		}
	}
	if v2 {
		var cert signingCertificateV2
		if err := decodeAttribute(oidAttrSigningCertV2, &cert); err != nil {
			return err
		}
		sum := sha256.Sum256(tsaCertDER)
		if len(cert.Certs) == 0 || !bytes.Equal(cert.Certs[0].CertHash, sum[:]) {
			return errors.New("crypto: timestamp CMS ESSv2 certificate identifier does not match its signer")
		}
	}
	// The exact signer has already passed the caller's chain/profile checks.
	// Verify checks its actual CMS signature and messageDigest, not containment
	// of certificate or imprint bytes in an otherwise unauthenticated blob.
	if err := p7.Verify(); err != nil {
		return fmt.Errorf("crypto: timestamp CMS signature is invalid: %w", err)
	}
	info, err := parseVerifiedTimestampInfo(content, signer)
	if err != nil {
		return err
	}
	if info.Version != 1 || !timestampSHA256Algorithm(info.MessageImprint.HashAlgorithm) ||
		!bytes.Equal(info.MessageImprint.HashedMessage, expected.HashedMessage) ||
		len(expected.HashedMessage) != sha256.Size || info.Policy.String() != expected.PolicyOID ||
		info.SerialNumber == nil || !info.SerialNumber.IsUint64() || info.SerialNumber.Uint64() != expected.SerialNumber {
		return errors.New("crypto: timestamp CMS signed fields do not match the verified manifest")
	}
	// Historical EncodeTSTInfo uses encoding/asn1's whole-second time encoding,
	// while the independently signed JSON manifest retains nanoseconds. Accept
	// that exact precision mapping, not a duration tolerance. A fractional CMS
	// time, when supplied, must equal the authenticated manifest exactly.
	if !info.GenTime.Equal(expected.GenTime) &&
		(info.GenTime.Nanosecond() != 0 || !info.GenTime.Equal(expected.GenTime.Truncate(time.Second))) {
		return errors.New("crypto: timestamp CMS time does not match the verified manifest")
	}
	if expected.Nonce != nil && (info.Nonce == nil || info.Nonce.Cmp(expected.Nonce) != 0) {
		return errors.New("crypto: timestamp CMS nonce does not match the request")
	}
	return nil
}

func timestampSHA256Algorithm(algorithm pkix.AlgorithmIdentifier) bool {
	return algorithm.Algorithm.Equal(oidDigestSHA256) &&
		(len(algorithm.Parameters.FullBytes) == 0 || bytes.Equal(algorithm.Parameters.FullBytes, []byte{5, 0}))
}

// timestampInfoWithOptions includes the complete RFC 3161 TSTInfo field order.
// The encoder omits accuracy, ordering, TSA name and extensions, but their
// presence in a valid token must not make a nonce disappear during decoding.
type timestampInfoWithOptions struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint asn1MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Accuracy       struct {
		Seconds int `asn1:"optional"`
		Millis  int `asn1:"optional,tag:0"`
		Micros  int `asn1:"optional,tag:1"`
	} `asn1:"optional"`
	Ordering   bool             `asn1:"optional"`
	Nonce      *big.Int         `asn1:"optional"`
	TSA        asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions []pkix.Extension `asn1:"optional,tag:1"`
}

func parseVerifiedTimestampInfo(content []byte, signer *x509.Certificate) (timestampInfoWithOptions, error) {
	var info timestampInfoWithOptions
	rest, err := asn1.Unmarshal(content, &info)
	if err != nil || len(rest) != 0 {
		return info, errors.New("crypto: timestamp CMS content is not a complete TSTInfo")
	}
	// encoding/asn1 allows unknown trailing struct fields. Check the complete
	// sequence as well so signed garbage, duplicate options and future critical
	// fields cannot be silently ignored by a successful verification receipt.
	var fields []asn1.RawValue
	if rest, err := asn1.Unmarshal(content, &fields); err != nil || len(rest) != 0 || len(fields) < 5 {
		return info, errors.New("crypto: malformed timestamp fields")
	}
	index := 5
	options := []struct{ class, tag int }{
		{asn1.ClassUniversal, asn1.TagSequence}, {asn1.ClassUniversal, asn1.TagBoolean},
		{asn1.ClassUniversal, asn1.TagInteger}, {asn1.ClassContextSpecific, 0}, {asn1.ClassContextSpecific, 1},
	}
	for option, tag := range options {
		if index == len(fields) || fields[index].Class != tag.class || fields[index].Tag != tag.tag {
			continue
		}
		field := fields[index]
		index++
		switch option {
		case 0:
			if err := verifyTimestampAccuracy(field.FullBytes); err != nil {
				return info, err
			}
		case 1:
			if !info.Ordering {
				return info, errors.New("crypto: timestamp DER must omit default false ordering")
			}
		case 2:
			if info.Nonce == nil || info.Nonce.Sign() < 0 {
				return info, errors.New("crypto: timestamp nonce must be a nonnegative integer")
			}
		case 3:
			if !timestampNameMatchesCertificate(field, signer) {
				return info, errors.New("crypto: timestamp TSA name does not match its signer certificate")
			}
		}
	}
	if index != len(fields) {
		return info, errors.New("crypto: timestamp has unexpected or repeated fields")
	}
	seen := make(map[string]bool)
	for _, extension := range info.Extensions {
		name := extension.Id.String()
		if extension.Critical || seen[name] {
			return info, errors.New("crypto: timestamp has an unsupported critical or duplicate extension")
		}
		seen[name] = true
	}
	return info, nil
}

func verifyTimestampAccuracy(der []byte) error {
	var fields []asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &fields); err != nil || len(rest) != 0 {
		return errors.New("crypto: malformed timestamp accuracy")
	}
	last := -1
	for _, field := range fields {
		index, params := -1, ""
		if field.Class == asn1.ClassUniversal && field.Tag == asn1.TagInteger {
			index = 0
		} else if field.Class == asn1.ClassContextSpecific && (field.Tag == 0 || field.Tag == 1) {
			index, params = field.Tag+1, fmt.Sprintf("tag:%d", field.Tag)
		}
		var value int
		rest, err := asn1.UnmarshalWithParams(field.FullBytes, &value, params)
		if index <= last || err != nil || len(rest) != 0 || value < 0 || (index > 0 && (value == 0 || value > 999)) {
			return errors.New("crypto: invalid timestamp accuracy fields")
		}
		last = index
	}
	return nil
}

func timestampNameMatchesCertificate(field asn1.RawValue, signer *x509.Certificate) bool {
	var name asn1.RawValue
	rest, err := asn1.Unmarshal(field.Bytes, &name)
	if err != nil || len(rest) != 0 || name.Class != asn1.ClassContextSpecific {
		return false
	}
	if name.Tag == 4 && name.IsCompound && bytes.Equal(name.Bytes, signer.RawSubject) {
		return true
	}
	for _, extension := range signer.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var names []asn1.RawValue
		if rest, err := asn1.Unmarshal(extension.Value, &names); err != nil || len(rest) != 0 {
			return false
		}
		for _, candidate := range names {
			if bytes.Equal(candidate.FullBytes, name.FullBytes) {
				return true
			}
		}
	}
	return false
}
