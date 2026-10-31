// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto/jose"
)

func TestVerificationKeysFileRefusesManagedRestoreAliases(t *testing.T) {
	base := t.TempDir()
	managed := filepath.Join(base, "managed-data")
	if err := os.MkdirAll(managed, 0700); err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateRSASigningKey("pinned-receipt-public")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := key.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(managed, "public.json")
	if err := os.WriteFile(file, wire, 0600); err != nil {
		t.Fatal(err)
	}
	independent := filepath.Join(base, "independent-public.json")
	if err := os.WriteFile(independent, wire, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "managed-alias")
	if err := os.Symlink(managed, alias); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{file, filepath.Join(alias, "public.json")} {
		if _, err := LoadVerificationKeysFile(candidate, []string{managed}); err == nil {
			t.Fatal("managed restore could replace its own historical verifier")
		}
	}
	if _, err := LoadVerificationKeysFile(independent, []string{alias}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerificationKeysFile(independent, nil); err == nil {
		t.Fatal("public trust accepted without declared restore boundaries")
	}
}
