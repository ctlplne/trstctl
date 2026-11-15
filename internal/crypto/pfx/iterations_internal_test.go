// SPDX-License-Identifier: BUSL-1.1

package pfx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// x2l8TrustStore is a certificate-only PKCS#12 file as enc writes it.
func x2l8TrustStore(t *testing.T, enc *pkcs12.Encoder, password string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x2l8.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	data, err := enc.EncodeTrustStore([]*x509.Certificate{cert}, password)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func x2l8Marshal(t *testing.T, v any) []byte {
	t.Helper()
	out, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// x2l8Explicit0 is v's encoding inside an explicit [0], as a field the
// reader decodes with tag:0,explicit expects.
func x2l8Explicit0(t *testing.T, inner []byte) asn1.RawValue {
	t.Helper()
	return asn1.RawValue{FullBytes: x2l8Marshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})}
}

// x2l8WithMACIterations rewrites the file's MAC iteration count to n (0
// keeps the file's own): the legacy MAC's own count, or a PBMAC1 MAC's PBKDF2
// count.
func x2l8WithMACIterations(t *testing.T, data []byte, n int) []byte {
	t.Helper()
	var pdu pfxPDU
	if err := strictUnmarshal(data, &pdu); err != nil {
		t.Fatal(err)
	}
	if pdu.MacData.Mac.Algorithm.Algorithm.Equal(oidPBMAC1) {
		var params pbmac1Params
		if err := strictUnmarshal(pdu.MacData.Mac.Algorithm.Parameters.FullBytes, &params); err != nil {
			t.Fatal(err)
		}
		var kdf pbkdf2Params
		if err := strictUnmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			kdf.Iterations = n
		}
		params.KDF.Parameters = asn1.RawValue{FullBytes: x2l8Marshal(t, kdf)}
		pdu.MacData.Mac.Algorithm.Parameters = asn1.RawValue{FullBytes: x2l8Marshal(t, params)}
	} else if n != 0 {
		pdu.MacData.Iterations = n
	}
	pdu.AuthSafe.Content = x2l8Explicit0(t, pdu.AuthSafe.Content.Bytes)
	return x2l8Marshal(t, pdu)
}

// x2l8WithContentIterations rewrites the encrypted contents' key-derivation
// count to n (0 keeps the file's own) and recomputes the file's legacy MAC
// with password, so the file still opens and the reader reaches the
// contents' key derivation.
func x2l8WithContentIterations(t *testing.T, data []byte, password string, n int) []byte {
	t.Helper()
	var pdu pfxPDU
	if err := strictUnmarshal(data, &pdu); err != nil {
		t.Fatal(err)
	}
	var authSafe []byte
	if err := strictUnmarshal(pdu.AuthSafe.Content.Bytes, &authSafe); err != nil {
		t.Fatal(err)
	}
	var contents []contentInfo
	if err := strictUnmarshal(authSafe, &contents); err != nil {
		t.Fatal(err)
	}
	changed := false
	for i, ci := range contents {
		if !ci.ContentType.Equal(oidEncryptedData) {
			contents[i].Content = x2l8Explicit0(t, ci.Content.Bytes)
			continue
		}
		var ed encryptedData
		if err := strictUnmarshal(ci.Content.Bytes, &ed); err != nil {
			t.Fatal(err)
		}
		alg := &ed.EncryptedContentInfo.ContentEncryptionAlgorithm
		if alg.Algorithm.Equal(oidPBES2) {
			var params pbes2Params
			if err := strictUnmarshal(alg.Parameters.FullBytes, &params); err != nil {
				t.Fatal(err)
			}
			var kdf pbkdf2Params
			if err := strictUnmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				kdf.Iterations = n
			}
			params.KDF.Parameters = asn1.RawValue{FullBytes: x2l8Marshal(t, kdf)}
			alg.Parameters = asn1.RawValue{FullBytes: x2l8Marshal(t, params)}
		} else {
			var params pbeParams
			if err := strictUnmarshal(alg.Parameters.FullBytes, &params); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				params.Iterations = n
			}
			alg.Parameters = asn1.RawValue{FullBytes: x2l8Marshal(t, params)}
		}
		contents[i].Content = x2l8Explicit0(t, x2l8Marshal(t, ed))
		changed = true
	}
	if !changed {
		t.Fatal("the file has no encrypted contents")
	}
	authSafe = x2l8Marshal(t, contents)
	pdu.AuthSafe.Content = x2l8Explicit0(t, x2l8Marshal(t, authSafe))
	h, v, ok := hashFor(pdu.MacData.Mac.Algorithm.Algorithm)
	if !ok {
		t.Fatalf("not a legacy MAC: %s", pdu.MacData.Mac.Algorithm.Algorithm)
	}
	bmp, err := bmpPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(h, pkcs12KDF(h, v, pdu.MacData.MacSalt, bmp, pdu.MacData.Iterations, 3, h().Size()))
	m.Write(authSafe)
	pdu.MacData.Mac.Digest = m.Sum(nil)
	return x2l8Marshal(t, pdu)
}

// TestKeyDerivationIterationCountsAreBoundedX2L8: every key derivation the
// certificate-only reader runs takes its iteration count from the file, so
// each is bounded at 2^22 (BCFKS's bound) before any hashing: a file naming
// 2^31-1 for the legacy MAC, a PBMAC1 MAC, PBE-encrypted contents or PBES2
// contents is refused at once, naming the derivation, by ChainDER and by the
// key inventory, which would otherwise hash it once per password it tries.
// The same files rewritten with their own counts still read (so the rewrite
// is the only change), and the bound itself is accepted.
func TestKeyDerivationIterationCountsAreBoundedX2L8(t *testing.T) {
	const password = "x2l8-password"
	const hostile = 1<<31 - 1
	if boundedIterations("a key", maxKDFIterations) != nil || boundedIterations("a key", maxKDFIterations+1) == nil {
		t.Fatalf("the bound is not 1..%d", maxKDFIterations)
	}
	for _, tc := range []struct {
		name    string
		enc     *pkcs12.Encoder
		mutate  func(*testing.T, []byte, int) []byte
		wantKDF string
	}{
		{"legacy MAC (LegacyRC2)", pkcs12.LegacyRC2, x2l8WithMACIterations, "the MAC key"},
		{"PBMAC1 MAC (Modern2026)", pkcs12.Modern2026, x2l8WithMACIterations, "the PBMAC1 MAC key"},
		{"PBE contents (LegacyDES)", pkcs12.LegacyDES, func(t *testing.T, d []byte, n int) []byte { return x2l8WithContentIterations(t, d, password, n) }, "the content key"},
		{"PBES2 contents (Modern2023)", pkcs12.Modern2023, func(t *testing.T, d []byte, n int) []byte { return x2l8WithContentIterations(t, d, password, n) }, "the PBES2 content key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := x2l8TrustStore(t, tc.enc, password)
			if chain, _, err := ChainDER(tc.mutate(t, data, 0), password); err != nil || len(chain) != 1 {
				t.Fatalf("the file rewritten with its own iteration counts: %d certificates, %v", len(chain), err)
			}
			hostileFile := tc.mutate(t, data, hostile)
			start := time.Now()
			_, _, err := ChainDER(hostileFile, password)
			if err == nil || !strings.Contains(err.Error(), tc.wantKDF) || !strings.Contains(err.Error(), "2147483647 key-derivation iterations") {
				t.Fatalf("ChainDER over %s at 2^31-1 = %v", tc.name, err)
			}
			if _, _, err := KeyEntries(hostileFile, password); err == nil || !strings.Contains(err.Error(), "key-derivation iterations") {
				t.Fatalf("KeyEntries over %s at 2^31-1 = %v", tc.name, err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("the refusals took %s; they must come before any hashing", elapsed)
			}
		})
	}
}
