// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

func TestReadBreakglassVerifierMaterialRejectsTrailingPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "breakglass-ca.pem")
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	raw = append(raw, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{4, 5, 6}})...)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPEMOrDERFile(path, "CERTIFICATE"); err == nil {
		t.Fatal("certificate plus trailing private-key PEM was accepted as verifier material")
	}
}

func TestReadBreakglassVerifierMaterialAllowsWhitespaceAroundPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "breakglass-ca.pem")
	want := []byte{1, 2, 3}
	raw := append([]byte("\n\t"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: want})...)
	raw = append(raw, '\r', '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readPEMOrDERFile(path, "CERTIFICATE")
	if err != nil {
		t.Fatalf("read PEM with surrounding whitespace: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded PEM = %x, want %x", got, want)
	}
}

func TestBreakglassVerifierMaterialPreservesDEREndingInWhitespace(t *testing.T) {
	caSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caSigner.Destroy)
	ca, err := crypto.SelfSignedHierarchyCA(caSigner, crypto.HierarchyCAProfile{
		CommonName: "Whitespace DER Verifier CA", MaxPathLen: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	caDER := append([]byte(nil), ca.CertificateDER...)
	caDER[len(caDER)-1] = ' ' // A signature octet may equal ASCII whitespace; the DER framing is unchanged.
	publicDER, err := crypto.PublicKeyDERFromCert(caDER)
	if err != nil {
		t.Fatalf("fixture must remain syntactically valid DER: %v", err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.der")
	publicPath := filepath.Join(dir, "public.der")
	if err := os.WriteFile(caPath, caDER, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, publicDER, 0o600); err != nil {
		t.Fatal(err)
	}
	gotCA, gotPublic, err := breakglassVerifierMaterialFromConfig(config.Breakglass{
		Enabled: true, CACertFile: caPath, PublicKeyFile: publicPath,
	})
	if err != nil {
		t.Fatalf("load valid DER ending in whitespace: %v", err)
	}
	if !bytes.Equal(gotCA, caDER) || !bytes.Equal(gotPublic, publicDER) {
		t.Fatal("break-glass verifier material mutated raw DER bytes")
	}
}

func TestBreakglassVerifierMaterialRequiresCertificatePublicKeyMatch(t *testing.T) {
	caSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caSigner.Destroy)
	otherSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherSigner.Destroy)
	ca, err := crypto.SelfSignedHierarchyCA(caSigner, crypto.HierarchyCAProfile{CommonName: "Verifier CA", MaxPathLen: 1, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	publicPath := filepath.Join(dir, "public.pem")
	if err := os.WriteFile(caPath, ca.CertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, crypto.MarshalPublicKeyPEM(otherSigner.Public().DER), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := breakglassVerifierMaterialFromConfig(config.Breakglass{
		Enabled: true, CACertFile: caPath, PublicKeyFile: publicPath,
	}); err == nil {
		t.Fatal("reconciliation verifier accepted a public key unrelated to its CA certificate")
	}
	if err := os.WriteFile(publicPath, crypto.MarshalPublicKeyPEM(caSigner.Public().DER), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := breakglassVerifierMaterialFromConfig(config.Breakglass{
		Enabled: true, CACertFile: caPath, PublicKeyFile: publicPath,
	}); err != nil {
		t.Fatalf("matching reconciliation verifier material: %v", err)
	}
}
