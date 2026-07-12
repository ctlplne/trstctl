// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import (
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestSPIFFEHybridAdditionalSVIDInteroperatesWithOpenSSL(t *testing.T) {
	openssl := requireOpenSSLMLDSA(t)
	caKey, err := boundarycrypto.GenerateLockedKey(boundarycrypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := boundarycrypto.SelfSignedCACert(caKey, "SPIFFE hybrid CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewSPIFFEHybridSVIDIssuer(caDER, caKey)
	if err != nil {
		t.Fatal(err)
	}
	const id = "spiffe://example.org/ns/default/sa/payments"
	got, err := issuer.IssueAdditionalX509SVID(context.Background(), id, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(got.PrivateKeyPKCS8)
	if got.Hint != SPIFFEHybridMLDSAHint {
		t.Fatalf("hint = %q", got.Hint)
	}
	if err := boundarycrypto.VerifyLeafSignedByCA(got.CertificateDER, caDER); err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(got.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.URIs) != 1 || info.URIs[0] != id {
		t.Fatalf("SVID URI SANs = %v", info.URIs)
	}

	dir := t.TempDir()
	caPath, certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "svid.pem"), filepath.Join(dir, "svid-key.der")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: got.CertificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, got.PrivateKeyPKCS8, 0o600); err != nil {
		t.Fatal(err)
	}
	runOpenSSL(t, openssl, "verify", "-CAfile", caPath, certPath)
	runOpenSSL(t, openssl, "pkey", "-inform", "DER", "-in", keyPath, "-check", "-noout")
	text := runOpenSSL(t, openssl, "x509", "-in", certPath, "-noout", "-text")
	if !strings.Contains(string(text), "ML-DSA-65") || !strings.Contains(string(text), id) {
		t.Fatalf("OpenSSL did not consume hybrid PQ SVID:\n%s", text)
	}
}
