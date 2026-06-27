package crypto

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// ESTChannelBindingLength is the SHA-256-sized tls-server-end-point binding
// length used by EST profiles in trstctl. The binding is the digest of the
// served TLS certificate DER and is signed into the CSR as a channel proof.
const ESTChannelBindingLength = 32

var (
	// ErrESTChannelBindingMissing means a binding-required EST profile received a
	// CSR with no usable signed channel-binding attribute.
	ErrESTChannelBindingMissing = errors.New("crypto: EST channel binding missing")
	// ErrESTChannelBindingMismatch means the CSR carried a binding, but it does not
	// match the server certificate the EST endpoint is serving.
	ErrESTChannelBindingMismatch = errors.New("crypto: EST channel binding mismatch")

	oidESTChannelBindingTLSExporter = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 56}
	oidESTCMCEnrollmentBinding      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 43}
)

// TLSServerEndPoint computes the tls-server-end-point channel-binding value from
// a served certificate's DER bytes. It lives in internal/crypto so EST never
// imports crypto/x509 or hash packages directly (AN-3).
func TLSServerEndPoint(certDER []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse tls-server-end-point certificate: %w", err)
	}
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		sum := sha512.Sum384(cert.Raw)
		return sum[:], nil
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		sum := sha512.Sum512(cert.Raw)
		return sum[:], nil
	default:
		sum := sha256.Sum256(cert.Raw)
		return sum[:], nil
	}
}

// VerifyESTChannelBinding checks the CSR's signed channel-binding attribute
// against the served TLS certificate. Absence is allowed only when required=false;
// a present mismatch always fails, even for optional profiles.
func VerifyESTChannelBinding(csrDER, servedCertDER []byte, required bool) error {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("crypto: parse EST CSR for channel binding: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("crypto: verify EST CSR before channel binding: %w", err)
	}
	got, present, err := extractESTChannelBinding(csr.RawTBSCertificateRequest)
	if err != nil {
		return err
	}
	if !present {
		if required {
			return ErrESTChannelBindingMissing
		}
		return nil
	}
	want, err := TLSServerEndPoint(servedCertDER)
	if err != nil {
		return err
	}
	if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 || !bytes.Equal(got, want) {
		return ErrESTChannelBindingMismatch
	}
	return nil
}

func appendESTChannelBindingAttribute(req *x509.CertificateRequest, binding []byte) error {
	if len(binding) != ESTChannelBindingLength {
		return fmt.Errorf("crypto: EST channel binding length %d, want %d", len(binding), ESTChannelBindingLength)
	}
	req.Attributes = append(req.Attributes, pkix.AttributeTypeAndValueSET{ //nolint:staticcheck // EST channel binding is a signed PKCS#10 attribute, not an extension.
		Type: oidESTChannelBindingTLSExporter,
		Value: [][]pkix.AttributeTypeAndValue{{
			{Type: oidESTChannelBindingTLSExporter, Value: asn1.RawValue{
				Class: asn1.ClassUniversal,
				Tag:   asn1.TagOctetString,
				Bytes: append([]byte(nil), binding...),
			}},
		}},
	})
	return nil
}

func extractESTChannelBinding(tbs []byte) ([]byte, bool, error) {
	if len(tbs) == 0 {
		return nil, false, nil
	}
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(tbs, &outer)
	if err != nil {
		return nil, false, fmt.Errorf("crypto: parse CSR TBS for channel binding: %w", err)
	}
	if len(rest) != 0 {
		return nil, false, fmt.Errorf("crypto: CSR TBS channel binding parse left %d trailing bytes", len(rest))
	}
	if outer.Tag != asn1.TagSequence {
		return nil, false, fmt.Errorf("crypto: CSR TBS tag %d not SEQUENCE", outer.Tag)
	}
	rest = outer.Bytes
	for _, label := range []string{"version", "subject", "subjectPublicKeyInfo"} {
		var skipped asn1.RawValue
		next, err := asn1.Unmarshal(rest, &skipped)
		if err != nil {
			return nil, false, fmt.Errorf("crypto: skip CSR TBS %s: %w", label, err)
		}
		rest = next
	}
	if len(rest) == 0 {
		return nil, false, nil
	}
	var attrs asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &attrs); err != nil {
		return nil, false, nil
	}
	if attrs.Class != asn1.ClassContextSpecific || attrs.Tag != 0 {
		return nil, false, nil
	}
	attrBytes := attrs.Bytes
	for len(attrBytes) > 0 {
		var one asn1.RawValue
		next, err := asn1.Unmarshal(attrBytes, &one)
		if err != nil {
			return nil, false, fmt.Errorf("crypto: parse CSR channel-binding attribute: %w", err)
		}
		attrBytes = next
		if one.Tag != asn1.TagSequence {
			continue
		}
		var oid asn1.ObjectIdentifier
		afterOID, err := asn1.Unmarshal(one.Bytes, &oid)
		if err != nil {
			continue
		}
		if !oid.Equal(oidESTChannelBindingTLSExporter) && !oid.Equal(oidESTCMCEnrollmentBinding) {
			continue
		}
		binding, err := extractESTChannelBindingFromSet(afterOID)
		if err != nil {
			return nil, false, err
		}
		return binding, true, nil
	}
	return nil, false, nil
}

func extractESTChannelBindingFromSet(der []byte) ([]byte, error) {
	var setWrap asn1.RawValue
	rest, err := asn1.Unmarshal(der, &setWrap)
	if err != nil {
		return nil, fmt.Errorf("%w: parse EST channel-binding SET: %v", ErrESTChannelBindingMissing, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: EST channel-binding SET has %d trailing bytes", ErrESTChannelBindingMissing, len(rest))
	}
	if setWrap.Tag != asn1.TagSet {
		return nil, fmt.Errorf("%w: EST channel-binding value tag %d not SET", ErrESTChannelBindingMissing, setWrap.Tag)
	}
	return extractESTChannelBindingValue(setWrap.Bytes)
}

func extractESTChannelBindingValue(der []byte) ([]byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse EST channel-binding value: %v", ErrESTChannelBindingMissing, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: EST channel-binding value has %d trailing bytes", ErrESTChannelBindingMissing, len(rest))
	}
	switch raw.Tag {
	case asn1.TagOctetString:
		if len(raw.Bytes) != ESTChannelBindingLength {
			return nil, fmt.Errorf("%w: EST channel-binding length %d, want %d", ErrESTChannelBindingMissing, len(raw.Bytes), ESTChannelBindingLength)
		}
		return append([]byte(nil), raw.Bytes...), nil
	case asn1.TagSequence:
		var oid asn1.ObjectIdentifier
		afterOID, err := asn1.Unmarshal(raw.Bytes, &oid)
		if err != nil {
			return extractESTChannelBindingValue(raw.Bytes)
		}
		if oid.Equal(oidESTChannelBindingTLSExporter) || oid.Equal(oidESTCMCEnrollmentBinding) {
			return extractESTChannelBindingValue(afterOID)
		}
		return extractESTChannelBindingValue(raw.Bytes)
	case asn1.TagSet:
		return extractESTChannelBindingValue(raw.Bytes)
	default:
		return nil, fmt.Errorf("%w: EST channel-binding value tag %d", ErrESTChannelBindingMissing, raw.Tag)
	}
}
