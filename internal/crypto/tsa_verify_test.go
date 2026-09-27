// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func timestampVerificationFixture(t *testing.T) (TSTInfoParams, []byte, []byte, *LockedSigner) {
	t.Helper()
	root, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Destroy)
	rootDER, err := SelfSignedCACert(root, "Timestamp verification root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "Timestamp verifier fixture"}, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := SignTimestampingCertFromCSR(rootDER, root, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	params := TSTInfoParams{PolicyOID: "1.3.6.1.4.1.59551.2.1", HashedMessage: SHA256Sum([]byte("timestamp evidence")), SerialNumber: 739, GenTime: time.Now().UTC().Truncate(time.Second).Add(123456789 * time.Nanosecond), Nonce: big.NewInt(739)}
	info, err := EncodeTSTInfo(params)
	if err != nil {
		t.Fatal(err)
	}
	return params, cert, info, key
}

func timestampTestDER(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func timestampTestFields(t *testing.T, der []byte) []asn1.RawValue {
	t.Helper()
	var fields []asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &fields); err != nil || len(rest) != 0 {
		t.Fatalf("fixture sequence: %v", err)
	}
	return fields
}

func timestampTestRaw(t *testing.T, value any) asn1.RawValue {
	t.Helper()
	return asn1.RawValue{FullBytes: timestampTestDER(t, value)}
}

func TestVerifyTimeStampTokenBindsSignedAttributes(t *testing.T) {
	params, cert, info, key := timestampVerificationFixture(t)
	original, err := BuildTimeStampToken(info, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTimeStampToken(original, cert, params); err != nil {
		t.Fatalf("genuine control: %v", err)
	}
	for _, name := range []string{"wrong-content-type", "duplicate-content-type", "multiple-content-type-values", "missing-content-type", "missing-certificate-binding", "wrong-ess-v1", "wrong-ess-v2"} {
		t.Run(name, func(t *testing.T) {
			var envelope tsaContentInfo
			if _, err := asn1.Unmarshal(original, &envelope); err != nil {
				t.Fatal(err)
			}
			var signer tsaSignerInfo
			if _, err := asn1.Unmarshal(envelope.Content.SignerInfos.Bytes, &signer); err != nil {
				t.Fatal(err)
			}
			var attrs [][]byte
			for remaining := signer.SignedAttrs.Bytes; len(remaining) > 0; {
				var attribute tsaAttribute
				var err error
				remaining, err = asn1.Unmarshal(remaining, &attribute)
				if err != nil {
					t.Fatal(err)
				}
				isType := attribute.Type.Equal(oidAttrContentType)
				isV1, isV2 := attribute.Type.Equal(oidAttrSigningCert), attribute.Type.Equal(oidAttrSigningCertV2)
				if (name == "missing-content-type" && isType) || (name == "missing-certificate-binding" && (isV1 || isV2)) {
					continue
				}
				if name == "wrong-content-type" && isType {
					attribute.Values = asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: timestampTestDER(t, oidSignedData)}
				}
				if name == "multiple-content-type-values" && isType {
					value := timestampTestDER(t, oidCTTSTInfo)
					attribute.Values = asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: append(bytes.Clone(value), value...)}
				}
				if (name == "wrong-ess-v1" && isV1) || (name == "wrong-ess-v2" && isV2) {
					value := bytes.Clone(attribute.Values.Bytes)
					value[len(value)-1] ^= 1
					attribute.Values = asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: value}
				}
				encoded := timestampTestDER(t, attribute)
				attrs = append(attrs, encoded)
				if name == "duplicate-content-type" && isType {
					attrs = append(attrs, encoded)
				}
			}
			sortDERSet(attrs)
			body := bytes.Join(attrs, nil)
			signer.SignedAttrs = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: body}
			signer.Signature, err = SignMessage(key, reTagToSetOf(body))
			if err != nil {
				t.Fatal(err)
			}
			envelope.Content.SignerInfos = asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: timestampTestDER(t, signer)}
			changed := timestampTestDER(t, envelope)
			// The mathematical signature is valid. Reject the semantic defect,
			// rather than relying on a broken-signature fixture to hide it.
			p7, err := safeParsePKCS7(changed)
			if err != nil {
				t.Fatal(err)
			}
			if err := p7.Verify(); err != nil {
				t.Fatalf("replacement must have a valid CMS signature: %v", err)
			}
			if err := VerifyTimeStampToken(changed, cert, params); err == nil {
				t.Fatal("accepted contradictory or missing signed attributes")
			}
		})
	}
}

func TestVerifyTimeStampTokenParsesCompleteSignedInfo(t *testing.T) {
	params, cert, info, key := timestampVerificationFixture(t)
	leaf, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"original", "exact-fractional-time", "optional-fields", "wrong-fractional-time", "wrong-imprint-algorithm", "wrong-version", "negative-serial", "oversized-serial", "repeated-nonce", "negative-nonce", "wrong-nonce", "unknown-field", "critical-extension", "invalid-accuracy", "wrong-tsa-name"} {
		t.Run(name, func(t *testing.T) {
			fields := timestampTestFields(t, info)
			wantValid := name == "original" || name == "exact-fractional-time" || name == "optional-fields"
			switch name {
			case "exact-fractional-time", "wrong-fractional-time":
				at := params.GenTime
				if name == "wrong-fractional-time" {
					at = at.Add(time.Nanosecond)
				}
				fields[4] = asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte(at.Format("20060102150405.999999999Z"))}
			case "wrong-imprint-algorithm":
				fields[2] = timestampTestRaw(t, asn1MessageImprint{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}}, HashedMessage: params.HashedMessage})
			case "wrong-version":
				fields[0] = timestampTestRaw(t, 2)
			case "negative-serial":
				fields[3] = timestampTestRaw(t, big.NewInt(-1))
			case "oversized-serial":
				fields[3] = timestampTestRaw(t, new(big.Int).Lsh(big.NewInt(1), 65))
			case "repeated-nonce":
				fields = append(fields, fields[5])
			case "negative-nonce":
				fields[5] = timestampTestRaw(t, big.NewInt(-1))
			case "wrong-nonce":
				fields[5] = timestampTestRaw(t, big.NewInt(740))
			case "unknown-field":
				fields = append(fields, timestampTestRaw(t, []byte("ignored signed data")))
			case "critical-extension":
				extension := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}
				fields = append(fields, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: timestampTestDER(t, extension)})
			case "optional-fields", "invalid-accuracy":
				accuracy := struct {
					Seconds int
					Millis  int `asn1:"tag:0"`
				}{Seconds: 1, Millis: 25}
				if name == "invalid-accuracy" {
					accuracy.Millis = 1000
				}
				fields = append(fields[:5], timestampTestRaw(t, accuracy), timestampTestRaw(t, true), fields[5])
				name := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: leaf.RawSubject}
				fields = append(fields, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: timestampTestDER(t, name)})
			case "wrong-tsa-name":
				name := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("different.example.test")}
				fields = append(fields, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: timestampTestDER(t, name)})
			}
			changed, err := BuildTimeStampToken(timestampTestDER(t, fields), cert, key)
			if err != nil {
				t.Fatal(err)
			}
			p7, err := safeParsePKCS7(changed)
			if err != nil {
				t.Fatal(err)
			}
			if err := p7.Verify(); err != nil {
				t.Fatalf("fixture must be authentically signed: %v", err)
			}
			err = VerifyTimeStampToken(changed, cert, params)
			if (err == nil) != wantValid {
				t.Fatalf("valid=%v, verification error=%v", wantValid, err)
			}
		})
	}
}
