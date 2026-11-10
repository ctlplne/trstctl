// SPDX-License-Identifier: BUSL-1.1

package pfx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// RFC 2268 section 5's test vectors, run as decryptions.
func TestRC2DecryptsTheRFC2268Vectors(t *testing.T) {
	for _, tc := range []struct {
		key, plain, cipher string
		bits               int
	}{
		{"0000000000000000", "0000000000000000", "ebb773f993278eff", 63},
		{"ffffffffffffffff", "ffffffffffffffff", "278b27e42e2f0d49", 64},
		{"3000000000000000", "1000000000000001", "30649edf9be7d2c2", 64},
		{"88", "0000000000000000", "61a8a244adacccf0", 64},
		{"88bca90e90875a", "0000000000000000", "6ccf4308974c267f", 64},
		{"88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "1a807d272bbe5db1", 64},
		{"88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "2269552ab0f85ca6", 128},
	} {
		key, _ := hex.DecodeString(tc.key)
		ct, _ := hex.DecodeString(tc.cipher)
		block, err := newRC2(key, tc.bits)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 8)
		block.Decrypt(out, ct)
		if got := hex.EncodeToString(out); got != tc.plain {
			t.Fatalf("rc2 key %s/%d bits: decrypt %s = %s, want %s", tc.key, tc.bits, tc.cipher, got, tc.plain)
		}
	}
}

type testChain struct {
	key  *ecdsa.PrivateKey
	leaf *x509.Certificate
	cas  []*x509.Certificate
}

func newTestChain(t *testing.T) testChain {
	t.Helper()
	mk := func(name string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}
	root, rootKey := mk("X2-L3 root", true, nil, nil)
	inter, interKey := mk("X2-L3 intermediate", true, root, rootKey)
	leaf, leafKey := mk("x2l3.example.test", false, inter, interKey)
	return testChain{key: leafKey, leaf: leaf, cas: []*x509.Certificate{inter, root}}
}

func ders(certs ...*x509.Certificate) [][]byte {
	out := make([][]byte, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.Raw)
	}
	return out
}

func sameDERs(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// X2-L3: the certificate-only reader returns exactly what the library decoder
// returns (the key's certificate first, then the CAs) for every encoding the
// library writes, without decrypting the key; a wrong password is the same
// error; a certificate-only trust store has no key.
func TestCertificatesOnlyMatchesTheLibraryDecoderX2L3(t *testing.T) {
	chain := newTestChain(t)
	for name, enc := range map[string]*pkcs12.Encoder{
		"legacy RC2": pkcs12.LegacyRC2, "legacy 3DES": pkcs12.LegacyDES,
		"modern 2023": pkcs12.Modern2023, "modern 2026 (PBMAC1)": pkcs12.Modern2026,
	} {
		file, err := enc.Encode(chain.key, chain.leaf, chain.cas, "x2l3-password")
		if err != nil {
			t.Fatalf("%s: encode: %v", name, err)
		}
		_, libLeaf, libCAs, err := pkcs12.DecodeChain(file, "x2l3-password")
		if err != nil {
			t.Fatalf("%s: library decode: %v", name, err)
		}
		got, hasKey, err := certificatesOnly(file, "x2l3-password")
		if err != nil || !hasKey || !sameDERs(got, ders(append([]*x509.Certificate{libLeaf}, libCAs...)...)) {
			t.Fatalf("%s: certificatesOnly = %d certs, key %v, %v; want the library's leaf and CAs", name, len(got), hasKey, err)
		}
		if _, _, err := certificatesOnly(file, "wrong"); !errors.Is(err, ErrIncorrectPassword) {
			t.Fatalf("%s: wrong password = %v, want ErrIncorrectPassword", name, err)
		}
	}
	open, err := pkcs12.Passwordless.Encode(chain.key, chain.leaf, chain.cas, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, hasKey, err := certificatesOnly(open, ""); err != nil || !hasKey || !sameDERs(got, ders(chain.leaf, chain.cas[0], chain.cas[1])) {
		t.Fatalf("passwordless: %d certs, key %v, %v", len(got), hasKey, err)
	}
	store, err := pkcs12.Modern2023.EncodeTrustStore(chain.cas, "store")
	if err != nil {
		t.Fatal(err)
	}
	if got, hasKey, err := certificatesOnly(store, "store"); err != nil || hasKey || len(got) != 2 {
		t.Fatalf("trust store: %d certs, key %v, %v; want two certificates and no key", len(got), hasKey, err)
	}
}

// pkcs12MAC computes a SHA-256 PKCS #12 integrity MAC, to hand-build files.
func pkcs12MAC(t *testing.T, authSafe []byte, password string) macData {
	t.Helper()
	bmp, err := bmpPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("x2l3-mac-salt-16")
	key := pkcs12KDF(sha256.New, 64, salt, bmp, 2048, 3, 32)
	m := hmac.New(sha256.New, key)
	m.Write(authSafe)
	return macData{Mac: digestInfo{Algorithm: algorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, Digest: m.Sum(nil)}, MacSalt: salt, Iterations: 2048}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	out, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// X2-L3, the property itself: the key is never decrypted. A hand-built file
// whose shrouded key bag uses an algorithm nothing can decrypt (and whose CA
// certificate comes first) still yields its certificates — the key's own
// first, by localKeyId — and says it holds a key. The library decoder cannot
// read the file at all, because it decrypts the key on the way.
func TestCertificatesOnlyNeverDecryptsTheKeyX2L3(t *testing.T) {
	chain := newTestChain(t)
	keyID := []byte("x2l3-local-key-id")
	attr := pkcs12Attribute{ID: oidLocalKeyID, Value: asn1.RawValue{Tag: asn1.TagSet, Class: asn1.ClassUniversal, IsCompound: true, Bytes: mustMarshal(t, keyID)}}
	certBagFor := func(c *x509.Certificate, attrs []pkcs12Attribute) safeBag {
		value := mustMarshal(t, certBag{ID: oidX509Certificate, Data: c.Raw})
		return safeBag{ID: oidCertBag, Value: asn1.RawValue{FullBytes: mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: value})}, Attributes: attrs}
	}
	unreadableKey := mustMarshal(t, struct {
		Algorithm algorithmIdentifier
		Data      []byte
	}{algorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}}, bytes.Repeat([]byte{0x5a}, 48)})
	keyBag := safeBag{ID: oidShroudedKeyBag, Value: asn1.RawValue{FullBytes: mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: unreadableKey})}, Attributes: []pkcs12Attribute{attr}}
	dataInfo := func(bags []safeBag) contentInfo {
		inner := mustMarshal(t, mustMarshal(t, bags))
		return contentInfo{ContentType: oidData, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}}
	}
	authSafe := mustMarshal(t, []contentInfo{
		dataInfo([]safeBag{certBagFor(chain.cas[0], nil), certBagFor(chain.leaf, []pkcs12Attribute{attr})}),
		dataInfo([]safeBag{keyBag}),
	})
	file := mustMarshal(t, pfxPDU{
		Version:  3,
		AuthSafe: contentInfo{ContentType: oidData, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustMarshal(t, authSafe)}},
		MacData:  pkcs12MAC(t, authSafe, "x2l3-password"),
	})

	if _, _, _, err := pkcs12.DecodeChain(file, "x2l3-password"); err == nil {
		t.Fatal("the library decoder read a file whose key cannot be decrypted; the fixture proves nothing")
	}
	got, hasKey, err := ChainDER(file, "x2l3-password")
	if err != nil || !hasKey || !sameDERs(got, ders(chain.leaf, chain.cas[0])) {
		t.Fatalf("ChainDER of a file with an undecryptable key = %d certs, key %v, %v; want the leaf (by localKeyId) then its CA, and a key", len(got), hasKey, err)
	}
	if _, _, err := ChainDER(file, "wrong"); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("wrong password = %v, want ErrIncorrectPassword", err)
	}
}

// X2-L3 against files a stock OpenSSL writes (its default PBES2/AES and its
// -legacy RC2 and 3DES encodings): the certificate-only reader returns what the
// library decoder returns. Skipped where openssl, or its legacy provider, is
// missing.
func TestCertificatesOnlyReadsOpenSSLFilesX2L3(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed")
	}
	chain := newTestChain(t)
	dir := t.TempDir()
	keyDER, err := x509.MarshalPKCS8PrivateKey(chain.key)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, kind string, der []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	keyPath := write("key.pem", "PRIVATE KEY", keyDER)
	leafPath := write("leaf.pem", "CERTIFICATE", chain.leaf.Raw)
	caPath := filepath.Join(dir, "cas.pem")
	if err := os.WriteFile(caPath, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.cas[0].Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.cas[1].Raw})...), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, extra := range map[string][]string{"default": nil, "legacy": {"-legacy"}, "certpbe 3DES": {"-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1"}} {
		out := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".p12")
		args := append([]string{"pkcs12", "-export", "-inkey", keyPath, "-in", leafPath, "-certfile", caPath, "-passout", "pass:x2l3-openssl", "-out", out}, extra...)
		if msg, err := exec.Command(openssl, args...).CombinedOutput(); err != nil { // #nosec G204 -- the test runs the system openssl on its own files (CWE-78)
			t.Logf("%s: openssl cannot write it here (%v: %s)", name, err, msg)
			continue
		}
		file, err := os.ReadFile(out) // #nosec G304 -- the test's own file (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		_, libLeaf, libCAs, err := pkcs12.DecodeChain(file, "x2l3-openssl")
		if err != nil {
			t.Fatalf("%s: library decode: %v", name, err)
		}
		got, hasKey, err := certificatesOnly(file, "x2l3-openssl")
		if err != nil || !hasKey || !sameDERs(got, ders(append([]*x509.Certificate{libLeaf}, libCAs...)...)) {
			t.Fatalf("%s: certificatesOnly = %d certs, key %v, %v; want the library's leaf and CAs", name, len(got), hasKey, err)
		}
	}
}
