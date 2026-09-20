// SPDX-License-Identifier: BUSL-1.1

package tsa

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
)

var (
	oidSHA1    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidMD5Fuzz = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
)

// FuzzParseTimeStampReq hardens the served /tsa RFC 3161 TimeStampReq parser.
// The HTTP path bounds request bodies before calling parseTimeStampReq, so the
// fuzz target applies the same limit and then checks that every accepted DER
// request satisfies the parser's fail-closed invariants.
func FuzzParseTimeStampReq(f *testing.F) {
	addHexTimeStampReqSeed(f, "openssl sha256 certreq nonce", "30440201013031300d060960864801650304020105000420d66849599158b8d081bddc1a7aaa6872c70cb238a13d4283431a55d5eff221850209009394b523a53b39660101ff")
	addHexTimeStampReqSeed(f, "openssl sha256 certreq no nonce", "30390201013031300d0609608648016503040201050004201ef0fd9a2f34e3dc96a19654fa8defea8084e89514f856b68f320f3dd148d3040101ff")
	addHexTimeStampReqSeed(f, "openssl sha1 rejected", "30260201013021300906052b0e03021a05000414b7b62ef75db0a0dea67925da4f2c865f1fcbe2f2")

	validMinimal := marshalTimeStampReqSeed(f, asn1TimeStampReq{
		Version:        1,
		MessageImprint: fuzzMessageImprint(oidSHA256, bytes.Repeat([]byte{0x42}, 32)),
	})
	f.Add(validMinimal)
	f.Add(append(append([]byte(nil), validMinimal...), 0x00)) // trailing data
	f.Add([]byte(nil))
	f.Add([]byte("not a timestamp request"))
	f.Add([]byte{0x30})
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})

	addTimeStampReqSeed(f, asn1TimeStampReq{
		Version:        2,
		MessageImprint: fuzzMessageImprint(oidSHA256, bytes.Repeat([]byte{0x11}, 32)),
	})
	addTimeStampReqSeed(f, asn1TimeStampReq{
		Version:        1,
		MessageImprint: fuzzMessageImprint(oidSHA1, bytes.Repeat([]byte{0x22}, 20)),
	})
	addTimeStampReqSeed(f, asn1TimeStampReq{
		Version:        1,
		MessageImprint: fuzzMessageImprint(oidMD5Fuzz, bytes.Repeat([]byte{0x33}, 32)),
	})
	addTimeStampReqSeed(f, asn1TimeStampReq{
		Version:        1,
		MessageImprint: fuzzMessageImprint(oidSHA256, bytes.Repeat([]byte{0x44}, 31)),
	})
	addTimeStampReqSeed(f, asn1TimeStampReq{
		Version:        1,
		MessageImprint: fuzzMessageImprint(oidSHA256, bytes.Repeat([]byte{0x55}, 32)),
		Nonce:          big.NewInt(-1),
	})
	addTimeStampReqSeed(f, asn1TimeStampReq{
		Version:        1,
		MessageImprint: fuzzMessageImprint(oidSHA256, bytes.Repeat([]byte{0x66}, 32)),
		Nonce:          new(big.Int).Lsh(big.NewInt(1), 4096),
		CertReq:        true,
		Extensions: asn1.RawValue{
			FullBytes: derWrapFuzz(0xa0, bytes.Repeat([]byte{0x30, 0x00}, 2048)),
		},
	})

	f.Fuzz(func(t *testing.T, der []byte) {
		if len(der) > maxTimeStampReqBytes {
			return
		}
		parsed, err := parseTimeStampReq(der)
		if err != nil {
			return
		}
		if len(parsed.HashedMessage) != 32 {
			t.Fatalf("parseTimeStampReq accepted hashed message length %d, want 32", len(parsed.HashedMessage))
		}
		if parsed.Nonce != nil && parsed.Nonce.Sign() < 0 {
			t.Fatal("parseTimeStampReq accepted a negative nonce")
		}

		originalHash := append([]byte(nil), parsed.HashedMessage...)
		parsed.HashedMessage[0] ^= 0xff
		reparsed, err := parseTimeStampReq(der)
		if err != nil {
			t.Fatalf("parseTimeStampReq failed to reparse accepted DER: %v", err)
		}
		if !bytes.Equal(originalHash, reparsed.HashedMessage) {
			t.Fatal("parseTimeStampReq returned hashed message storage aliased to caller mutation")
		}
	})
}

func addHexTimeStampReqSeed(f *testing.F, name, hexDER string) {
	f.Helper()
	der, err := hex.DecodeString(hexDER)
	if err != nil {
		f.Fatalf("decode %s seed: %v", name, err)
	}
	f.Add(der)
}

func addTimeStampReqSeed(f *testing.F, req asn1TimeStampReq) {
	f.Helper()
	f.Add(marshalTimeStampReqSeed(f, req))
}

func marshalTimeStampReqSeed(f *testing.F, req asn1TimeStampReq) []byte {
	f.Helper()
	der, err := asn1.Marshal(req)
	if err != nil {
		f.Fatalf("marshal TimeStampReq seed: %v", err)
	}
	return der
}

func fuzzMessageImprint(oid asn1.ObjectIdentifier, hashed []byte) asn1MessageImprint {
	return asn1MessageImprint{
		HashAlgorithm: asn1AlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{Tag: 5},
		},
		HashedMessage: append([]byte(nil), hashed...),
	}
}

func derWrapFuzz(tag byte, body []byte) []byte {
	out := []byte{tag}
	switch {
	case len(body) < 128:
		out = append(out, byte(len(body))) // #nosec G115 -- crafted DER length byte for fuzz corpus; truncation is the crafted input (CWE-190)
	case len(body) <= 0xff:
		out = append(out, 0x81, byte(len(body))) // #nosec G115 -- crafted DER length byte for fuzz corpus (CWE-190)
	default:
		out = append(out, 0x82, byte(len(body)>>8), byte(len(body))) // #nosec G115 -- crafted DER length bytes for fuzz corpus (CWE-190)
	}
	return append(out, body...)
}
