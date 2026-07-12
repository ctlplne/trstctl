// SPDX-License-Identifier: MPL-2.0

package server

import (
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
