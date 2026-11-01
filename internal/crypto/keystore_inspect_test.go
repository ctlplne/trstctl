// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jks"
	"trstctl.com/trstctl/internal/crypto/pfx"
)

// X2: a JKS and a PKCS#12 keystore report key type and size from the entry
// certificate, with the public-key fingerprint basis private-key discovery
// uses, and nothing that could carry the private key.
func TestInspectKeystoreReportsKeyTypeAndSizeWithoutKeyMaterial(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKeyPEM, rsaCertPEM, rsaCert := keystoreTestCredential(t, rsaKey, "jks.example.test")
	ecKeyPEM, ecCertPEM, ecCert := keystoreTestCredential(t, ecKey, "p12.example.test")

	jksData, err := jks.EncodeDeterministic(rsaKeyPEM, rsaCertPEM, "storepass", "tomcat")
	if err != nil {
		t.Fatal(err)
	}
	p12Data, err := pfx.EncodeDeterministic(ecKeyPEM, ecCertPEM, "p12pass")
	if err != nil {
		t.Fatal(err)
	}

	report, err := InspectKeystore(jksData, [][]byte{[]byte("wrong"), []byte("storepass")})
	if err != nil {
		t.Fatal(err)
	}
	if report.Format != "JKS" || !report.IntegrityVerified || len(report.Keys) != 1 {
		t.Fatalf("JKS report = %+v", report)
	}
	key := report.Keys[0]
	if key.Alias != "tomcat" || key.Algorithm != RSA2048 || key.KeyType != "RSA" || key.KeyBits != 2048 || key.ChainLength != 1 ||
		key.FingerprintSHA256 != SHA256Hex(rsaCert.RawSubjectPublicKeyInfo) || key.FingerprintBasis != "public-spki-sha256" {
		t.Fatalf("JKS key = %+v", key)
	}
	assertNoKeyMaterial(t, report, rsaKeyPEM)

	// JKS keeps certificates in the clear: without the password the entries
	// are still listed, marked unverified.
	unverified, err := InspectKeystore(jksData, nil)
	if err != nil || unverified.IntegrityVerified || len(unverified.Keys) != 1 || unverified.Keys[0].Algorithm != RSA2048 {
		t.Fatalf("JKS without its password = %+v, %v", unverified, err)
	}

	report, err = InspectKeystore(p12Data, [][]byte{[]byte("p12pass")})
	if err != nil {
		t.Fatal(err)
	}
	if report.Format != "PKCS12" || !report.IntegrityVerified || len(report.Keys) != 1 ||
		report.Keys[0].Algorithm != ECDSAP256 || report.Keys[0].KeyType != "ECDSA" || report.Keys[0].KeyBits != 256 || report.Keys[0].FingerprintSHA256 != SHA256Hex(ecCert.RawSubjectPublicKeyInfo) {
		t.Fatalf("PKCS#12 report = %+v", report)
	}
	assertNoKeyMaterial(t, report, ecKeyPEM)

	// A PKCS#12 file nobody can open lists nothing.
	if _, err := InspectKeystore(p12Data, [][]byte{[]byte("nope")}); !errors.Is(err, ErrKeystoreLocked) {
		t.Fatalf("PKCS#12 with a wrong password: %v, want ErrKeystoreLocked", err)
	}
	if _, err := InspectKeystore([]byte{0xCE, 0xCE, 0xCE, 0xCE, 0, 0, 0, 2}, nil); err == nil {
		t.Fatal("a JCEKS keystore was read")
	}
}

func keystoreTestCredential(t *testing.T, key any, cn string) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	signer := key.(stdcrypto.Signer)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert
}

func assertNoKeyMaterial(t *testing.T, report KeystoreReport, keyPEM []byte) {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	for _, leak := range []string{"PRIVATE KEY", base64.StdEncoding.EncodeToString(block.Bytes)[:32]} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("keystore report carries key material (%q)", leak)
		}
	}
}
