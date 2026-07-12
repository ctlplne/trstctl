// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import (
	"bytes"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestPureMLDSALeafInteroperatesWithStockOpenSSL(t *testing.T) {
	openssl := requireOpenSSLMLDSA(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "leaf-key.pem")
	csrPath := filepath.Join(dir, "leaf.csr")
	runOpenSSL(t, openssl, "genpkey", "-algorithm", "ML-DSA-65", "-out", keyPath)
	runOpenSSL(t, openssl, "req", "-new", "-key", keyPath,
		"-subj", "/CN=pure-mldsa.example", "-addext", "subjectAltName=DNS:pure-mldsa.example",
		"-outform", "DER", "-out", csrPath)
	csrDER, err := os.ReadFile(csrPath)
	if err != nil {
		t.Fatal(err)
	}
	info, recognized, err := ParsePureMLDSACSR(csrDER)
	if err != nil || !recognized {
		t.Fatalf("ParsePureMLDSACSR recognized=%v err=%v", recognized, err)
	}
	if info.KeyAlgorithm != string(MLDSA65) || info.CommonName != "pure-mldsa.example" {
		t.Fatalf("pure CSR info = %+v", info)
	}

	caKey, err := boundarycrypto.GenerateLockedKey(boundarycrypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := boundarycrypto.SelfSignedCACert(caKey, "trstctl PQC acceptance CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := SignLicensedLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, boundarycrypto.LeafProfile{})
	if err != nil {
		t.Fatalf("SignLicensedLeafFromCSRWithProfile: %v", err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	leafPath := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	verify := runOpenSSL(t, openssl, "verify", "-CAfile", caPath, leafPath)
	if !strings.Contains(string(verify), ": OK") {
		t.Fatalf("openssl verify output = %s", verify)
	}
	text := runOpenSSL(t, openssl, "x509", "-in", leafPath, "-noout", "-text")
	if !bytes.Contains(text, []byte("ML-DSA-65")) || !bytes.Contains(text, []byte("DNS:pure-mldsa.example")) {
		t.Fatalf("OpenSSL did not consume pure ML-DSA subject leaf:\n%s", text)
	}
}

func TestGeneratedMLDSAPKCS8InteroperatesWithStockOpenSSL(t *testing.T) {
	openssl := requireOpenSSLMLDSA(t)
	key, pkcs8, err := GenerateInteroperableMLDSAKey(MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	defer secret.Wipe(pkcs8)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.der")
	pubPath := filepath.Join(dir, "pub.der")
	if err := os.WriteFile(keyPath, pkcs8, 0o600); err != nil {
		t.Fatal(err)
	}
	runOpenSSL(t, openssl, "pkey", "-inform", "DER", "-in", keyPath, "-check", "-noout")
	runOpenSSL(t, openssl, "pkey", "-inform", "DER", "-in", keyPath, "-pubout", "-outform", "DER", "-out", pubPath)
	gotPub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	wantPub, err := boundarycrypto.MarshalOpaqueSubjectPublicKeyInfo(MLDSA65OID, key.Public().DER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPub, wantPub) {
		t.Fatal("OpenSSL derived a different ML-DSA public key from RFC 9881 seed PKCS#8")
	}
}

func requireOpenSSLMLDSA(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatalf("stock OpenSSL is required for ML-DSA interoperability: %v", err)
	}
	cmd := exec.Command(path, "list", "-signature-algorithms")
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("ML-DSA-65")) {
		t.Fatalf("stock OpenSSL lacks ML-DSA-65 support: %v\n%s", err, out)
	}
	return path
}

func runOpenSSL(t *testing.T, openssl string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(openssl, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}
