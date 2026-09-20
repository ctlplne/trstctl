// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
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
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("nothing secret here\n"), 0o644); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
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
	if !got.Restricted {
		t.Fatalf("private-key file metadata = restricted %v metadata %+v, want platform custody to be private", got.Restricted, got.Metadata)
	}
	if runtime.GOOS == "windows" {
		if got.Metadata["permission_model"] != "windows_dacl" || got.Metadata["file_mode"] != "" {
			t.Fatalf("Windows private-key metadata = %+v, want DACL authority without misleading POSIX mode", got.Metadata)
		}
	} else if got.Metadata["permission_model"] != "posix_mode" || got.Metadata["file_mode"] != "0600" {
		t.Fatalf("private-key file metadata = %+v, want restricted 0600 POSIX mode", got.Metadata)
	}
	for k, v := range got.Metadata {
		if strings.Contains(v, "PRIVATE KEY") {
			t.Fatalf("private-key metadata field %s exposed key bytes: %q", k, v)
		}
	}
}
