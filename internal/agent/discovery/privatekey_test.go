// SPDX-License-Identifier: MPL-2.0

package discovery

import (
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cryptoboundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestPrivateKeySourceDiscoversMetadataOnly(t *testing.T) {
	dir := t.TempDir()
	der, err := cryptoboundary.GeneratePKCS8(cryptoboundary.ECDSAP256)
	if err != nil {
		t.Fatalf("GeneratePKCS8: %v", err)
	}
	defer secret.Wipe(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer secret.Wipe(pemBytes)
	keyPath := filepath.Join(dir, "keys", "server.key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("nothing secret here\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	found, err := NewPrivateKeySource(dir).Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("private-key discovery found %d keys, want 1: %+v", len(found), found)
	}
	got := found[0]
	if got.Source != SourcePrivateKey || got.Location != keyPath || got.Format != "PKCS8" || got.Algorithm != cryptoboundary.ECDSAP256 || got.Fingerprint == "" {
		t.Fatalf("private-key finding = %+v, want classified ECDSA-P256 fixture", got)
	}
	if !got.Restricted || got.Metadata["file_mode"] != "0600" {
		t.Fatalf("private-key file metadata = restricted %v metadata %+v, want restricted 0600", got.Restricted, got.Metadata)
	}
	for k, v := range got.Metadata {
		if strings.Contains(v, "PRIVATE KEY") {
			t.Fatalf("private-key metadata field %s exposed key bytes: %q", k, v)
		}
	}
}
