// SPDX-License-Identifier: BUSL-1.1

package ctlog

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// RFC 6962 §3.2 and §3.5 enumerations a signed CT structure begins with.
const (
	sctVersionV1             = 0
	signatureTypeCertificate = 0
	signatureTypeTreeHash    = 1
	hashAlgorithmSHA256      = 4
	signatureAlgorithmRSA    = 1
	signatureAlgorithmECDSA  = 3
)

// ctPoisonOID marks a precertificate (RFC 6962 §3.1); the log signs the
// TBSCertificate without it.
var ctPoisonOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

// ctPrecertSigningEKU marks a precertificate signing certificate (RFC 6962
// §3.1), which changes what the log signs; such chains are not verified here.
var ctPrecertSigningEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}

// ErrNotVerifiable marks an SCT that cannot be checked from the chain it was
// given — a precertificate without the certificate that issued it, or one a
// precertificate signing certificate issued — which is no evidence the SCT is
// bad.
var ErrNotVerifiable = errors.New("ctlog: the SCT cannot be verified from this chain")

// SCT is one signed certificate timestamp a log returned from add-chain or
// add-pre-chain (RFC 6962 §3.2).
type SCT struct {
	Version    int
	LogID      []byte
	Timestamp  uint64
	Extensions []byte
	// Signature is the TLS DigitallySigned struct: hash and signature
	// algorithm bytes, a 16-bit length, then the signature.
	Signature []byte
}

// maxSCTResponse bounds the JSON an SCT response may hold.
const maxSCTResponse = 64 << 10

// ParseSCT parses an add-chain / add-pre-chain response body.
func ParseSCT(body []byte) (SCT, error) {
	if len(body) > maxSCTResponse {
		return SCT{}, errors.New("ctlog: SCT response is too large")
	}
	var raw struct {
		Version    int    `json:"sct_version"`
		ID         string `json:"id"`
		Timestamp  uint64 `json:"timestamp"`
		Extensions string `json:"extensions"`
		Signature  string `json:"signature"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return SCT{}, fmt.Errorf("ctlog: parse SCT: %w", err)
	}
	id, err := base64.StdEncoding.DecodeString(raw.ID)
	if err != nil || len(id) != sha256.Size {
		return SCT{}, errors.New("ctlog: SCT log id is not a SHA-256 hash")
	}
	extensions, err := base64.StdEncoding.DecodeString(raw.Extensions)
	if err != nil || len(extensions) > 0xffff {
		return SCT{}, errors.New("ctlog: SCT extensions are malformed")
	}
	signature, err := base64.StdEncoding.DecodeString(raw.Signature)
	if err != nil || len(signature) < 4 {
		return SCT{}, errors.New("ctlog: SCT signature is malformed")
	}
	if raw.Version != sctVersionV1 || raw.Timestamp == 0 {
		return SCT{}, errors.New("ctlog: SCT is not a version 1 timestamp")
	}
	return SCT{Version: raw.Version, LogID: id, Timestamp: raw.Timestamp, Extensions: extensions, Signature: signature}, nil
}

// LogID is the RFC 6962 log id: the SHA-256 of the log's DER public key.
func LogID(logKeySPKI []byte) []byte {
	sum := sha256.Sum256(logKeySPKI)
	return sum[:]
}

// VerifySCT checks an SCT against the log's public key for the chain it was
// returned for (chain[0] is the submitted certificate or precertificate,
// chain[1] its issuer) and returns the RFC 6962 Merkle leaf hash the log
// will include, for the inclusion check.
func VerifySCT(sct SCT, logKeySPKI []byte, chain [][]byte, precert bool) ([]byte, error) {
	if !bytes.Equal(sct.LogID, LogID(logKeySPKI)) {
		return nil, errors.New("ctlog: the SCT names another log than the configured key")
	}
	signedEntry, entryType, err := signedEntryFor(chain, precert)
	if err != nil {
		return nil, err
	}
	var signed []byte
	signed = append(signed, sctVersionV1, signatureTypeCertificate)
	signed = appendU64(signed, sct.Timestamp)
	signed = appendU16(signed, entryType)
	signed = append(signed, signedEntry...)
	signed = appendU16(signed, len(sct.Extensions))
	signed = append(signed, sct.Extensions...)
	if err := verifyDigitallySigned(logKeySPKI, signed, sct.Signature); err != nil {
		return nil, fmt.Errorf("ctlog: SCT signature: %w", err)
	}
	var leaf []byte
	leaf = append(leaf, leafVersionV1, leafTypeTimestamped)
	leaf = appendU64(leaf, sct.Timestamp)
	leaf = appendU16(leaf, entryType)
	leaf = append(leaf, signedEntry...)
	leaf = appendU16(leaf, len(sct.Extensions))
	leaf = append(leaf, sct.Extensions...)
	return MerkleLeafHash(leaf), nil
}

// signedEntryFor builds the RFC 6962 signed_entry for a submission: the
// certificate itself for x509_entry, or the issuer key hash and the
// precertificate's TBSCertificate without its poison for precert_entry.
func signedEntryFor(chain [][]byte, precert bool) ([]byte, int, error) {
	if len(chain) == 0 || len(chain[0]) == 0 {
		return nil, 0, errors.New("ctlog: no certificate to verify the SCT for")
	}
	if !precert {
		entry, err := appendASN1Cert(nil, chain[0])
		return entry, logEntryTypeX509, err
	}
	if len(chain) < 2 {
		return nil, 0, fmt.Errorf("%w: a precertificate SCT needs the issuer certificate", ErrNotVerifiable)
	}
	issuer, err := x509.ParseCertificate(chain[1])
	if err != nil {
		return nil, 0, fmt.Errorf("%w: parse precertificate issuer: %v", ErrNotVerifiable, err)
	}
	for _, eku := range issuer.UnknownExtKeyUsage {
		if eku.Equal(ctPrecertSigningEKU) {
			return nil, 0, fmt.Errorf("%w: precertificates signed by a precertificate signing certificate are not verified", ErrNotVerifiable)
		}
	}
	pre, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, 0, fmt.Errorf("ctlog: parse precertificate: %w", err)
	}
	if err := pre.CheckSignatureFrom(issuer); err != nil {
		return nil, 0, fmt.Errorf("%w: the chain's second certificate did not issue the precertificate", ErrNotVerifiable)
	}
	tbs, err := tbsWithoutPoison(pre.RawTBSCertificate)
	if err != nil {
		return nil, 0, err
	}
	keyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	entry := append([]byte(nil), keyHash[:]...)
	entry, err = appendASN1Cert(entry, tbs)
	return entry, logEntryTypePrecert, err
}

// tbsWithoutPoison re-encodes a TBSCertificate with the CT poison extension
// removed, which is what a log signs for a precertificate.
func tbsWithoutPoison(tbsDER []byte) ([]byte, error) {
	var tbs asn1.RawValue
	if rest, err := asn1.Unmarshal(tbsDER, &tbs); err != nil || len(rest) != 0 {
		return nil, errors.New("ctlog: precertificate TBSCertificate does not parse")
	}
	var fields []asn1.RawValue
	for rest := tbs.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			return nil, errors.New("ctlog: precertificate TBSCertificate does not parse")
		}
		fields = append(fields, field)
	}
	poisoned := false
	for i, field := range fields {
		// extensions [3] EXPLICIT Extensions
		if field.Class != asn1.ClassContextSpecific || field.Tag != 3 {
			continue
		}
		var extensions []asn1.RawValue
		if rest, err := asn1.Unmarshal(field.Bytes, &extensions); err != nil || len(rest) != 0 {
			return nil, errors.New("ctlog: precertificate extensions do not parse")
		}
		kept := make([]asn1.RawValue, 0, len(extensions))
		for _, extension := range extensions {
			var parsed struct {
				ID       asn1.ObjectIdentifier
				Critical bool `asn1:"optional"`
				Value    []byte
			}
			if _, err := asn1.Unmarshal(extension.FullBytes, &parsed); err != nil {
				return nil, errors.New("ctlog: precertificate extension does not parse")
			}
			if parsed.ID.Equal(ctPoisonOID) {
				poisoned = true
				continue
			}
			kept = append(kept, extension)
		}
		inner, err := asn1.Marshal(kept)
		if err != nil {
			return nil, err
		}
		wrapped, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: inner})
		if err != nil {
			return nil, err
		}
		fields[i] = asn1.RawValue{FullBytes: wrapped}
	}
	if !poisoned {
		return nil, errors.New("ctlog: the submitted precertificate carries no CT poison extension")
	}
	var body []byte
	for _, field := range fields {
		body = append(body, field.FullBytes...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

// verifyDigitallySigned checks a TLS DigitallySigned struct over message with
// the log key: SHA-256 with ECDSA or RSA, the two RFC 6962 allows.
func verifyDigitallySigned(logKeySPKI, message, digitallySigned []byte) error {
	if len(digitallySigned) < 4 {
		return errors.New("signature is truncated")
	}
	hashAlgorithm, signatureAlgorithm := digitallySigned[0], digitallySigned[1]
	length := int(digitallySigned[2])<<8 | int(digitallySigned[3])
	if hashAlgorithm != hashAlgorithmSHA256 || len(digitallySigned) != 4+length {
		return errors.New("signature is not a SHA-256 DigitallySigned struct")
	}
	signature := digitallySigned[4:]
	key, err := x509.ParsePKIXPublicKey(logKeySPKI)
	if err != nil {
		return fmt.Errorf("log key does not parse: %w", err)
	}
	digest := sha256.Sum256(message)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if signatureAlgorithm != signatureAlgorithmECDSA || !ecdsa.VerifyASN1(k, digest[:], signature) {
			return errors.New("does not verify")
		}
	case *rsa.PublicKey:
		if signatureAlgorithm != signatureAlgorithmRSA || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], signature) != nil {
			return errors.New("does not verify")
		}
	default:
		return errors.New("log key is neither ECDSA nor RSA")
	}
	return nil
}

func appendU16(b []byte, v int) []byte { return append(b, byte(v>>8), byte(v)) } // #nosec G115 -- RFC 6962 16-bit fields; callers bound v (CWE-190)

func appendU64(b []byte, v uint64) []byte {
	for shift := 56; shift >= 0; shift -= 8 {
		b = append(b, byte(v>>uint(shift))) // #nosec G115 -- byte extraction from a fixed-width value (CWE-190)
	}
	return b
}

func appendASN1Cert(b, der []byte) ([]byte, error) {
	if len(der) == 0 || len(der) >= 1<<24 {
		return nil, errors.New("ctlog: certificate length does not fit RFC 6962 framing")
	}
	n := len(der)
	b = append(b, byte(n>>16), byte(n>>8), byte(n)) // #nosec G115 -- bounded to 24 bits above (CWE-190)
	return append(b, der...), nil
}

// PrecertificateTBS returns a precertificate's TBSCertificate without its CT
// poison extension: the bytes a log signs and logs for it.
func PrecertificateTBS(precertDER []byte) ([]byte, error) {
	pre, err := x509.ParseCertificate(precertDER)
	if err != nil {
		return nil, fmt.Errorf("ctlog: parse precertificate: %w", err)
	}
	return tbsWithoutPoison(pre.RawTBSCertificate)
}

// ValidateLogKey accepts a CT log's DER SubjectPublicKeyInfo when it is an
// ECDSA or RSA key, the two RFC 6962 allows.
func ValidateLogKey(spki []byte) error {
	key, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return fmt.Errorf("ctlog: log key does not parse: %w", err)
	}
	switch key.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		return nil
	}
	return errors.New("ctlog: a log key is ECDSA or RSA")
}
