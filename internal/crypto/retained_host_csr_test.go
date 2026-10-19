// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestRetainedHostKeyCSRKeepsTheInstalledSubjectKey(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	privatePEM, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(privatePEM)
	wantSPKI := SHA256Hex(key.Public().DER)

	csr, err := CreateRetainedHostKeyCSR(privatePEM, "api.example.test", []string{"api.example.test"}, wantSPKI)
	if err != nil {
		t.Fatal(err)
	}
	info, err := InspectCSR(csr)
	if err != nil {
		t.Fatal(err)
	}
	if info.CommonName != "api.example.test" || len(info.DNSNames) != 1 || info.DNSNames[0] != "api.example.test" {
		t.Fatalf("retained key CSR changed its subject: %+v", info)
	}
	if bytes.Contains(csr, []byte("PRIVATE KEY")) {
		t.Fatal("public CSR contains private material")
	}
	if got := retainedCSRSPKISHA256(t, csr); got != wantSPKI {
		t.Fatalf("CSR changed installed subject key: got %s, want %s", got, wantSPKI)
	}
	if _, err := CreateRetainedHostKeyCSR(privatePEM, "api.example.test", []string{"api.example.test"}, strings.Repeat("0", 64)); err == nil {
		t.Fatal("changed predecessor SPKI was accepted")
	}
	if _, err := CreateRetainedHostKeyCSR(privatePEM, "", nil, wantSPKI); err == nil {
		t.Fatal("empty subject was accepted")
	}
	if _, err := CreateRetainedHostKeyCSR(append(append([]byte(nil), privatePEM...), privatePEM...), "api.example.test", []string{"api.example.test"}, wantSPKI); err == nil {
		t.Fatal("second private-key block was accepted")
	}
	if _, err := CreateRetainedHostKeyCSR(append([]byte("unreviewed prefix\n"), privatePEM...), "api.example.test", []string{"api.example.test"}, wantSPKI); err == nil {
		t.Fatal("private-key PEM with a skipped prefix was accepted")
	}
	if _, err := CreateRetainedHostKeyCSR(privatePEM, "api.example.test", []string{"api.example.test"}, "not-a-digest"); err == nil {
		t.Fatal("malformed predecessor SPKI was accepted")
	}
	block, _ := pem.Decode(privatePEM)
	defer secret.Wipe(block.Bytes)
	withEncryptionHeader := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes,
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}})
	defer secret.Wipe(withEncryptionHeader)
	if _, err := CreateRetainedHostKeyCSR(withEncryptionHeader, "api.example.test", []string{"api.example.test"}, wantSPKI); err == nil {
		t.Fatal("PEM encryption header was accepted without a reviewed unlock path")
	}
}

func TestRetainedHostKeyCSRAcceptsCommonInstalledPEMFormats(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  Algorithm
		pem  func([]byte) ([]byte, error)
	}{
		{name: "SEC1 ECDSA", alg: ECDSAP256, pem: func(der []byte) ([]byte, error) {
			parsed, err := x509.ParsePKCS8PrivateKey(der)
			if err != nil {
				return nil, err
			}
			defer wipeStdlibKey(parsed)
			encoded, err := x509.MarshalECPrivateKey(parsed.(*ecdsa.PrivateKey))
			if err != nil {
				return nil, err
			}
			defer secret.Wipe(encoded)
			return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), nil
		}},
		{name: "PKCS1 RSA", alg: RSA2048, pem: func(der []byte) ([]byte, error) {
			parsed, err := x509.ParsePKCS8PrivateKey(der)
			if err != nil {
				return nil, err
			}
			defer wipeStdlibKey(parsed)
			encoded := x509.MarshalPKCS1PrivateKey(parsed.(*rsa.PrivateKey))
			defer secret.Wipe(encoded)
			return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: encoded}), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GenerateLockedKey(tc.alg)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			der, err := key.PKCS8()
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(der)
			privatePEM, err := tc.pem(der)
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(privatePEM)
			wantSPKI := SHA256Hex(key.Public().DER)
			csr, err := CreateRetainedHostKeyCSR(privatePEM, "api.example.test", []string{"api.example.test"}, wantSPKI)
			if err != nil {
				t.Fatal(err)
			}
			if got := retainedCSRSPKISHA256(t, csr); got != wantSPKI {
				t.Fatalf("CSR public key %s differs from installed key %s", got, wantSPKI)
			}
		})
	}
}

func retainedCSRSPKISHA256(t *testing.T, csrDER []byte) string {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return SHA256Hex(spki)
}
