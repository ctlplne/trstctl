// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestControlPlaneHasNoAuditPrivateKeyOperations is the dependency-closure gate
// missing from the architecture linter (AN-4). Production audit private-key
// constructors/parsers may exist only inside the crypto boundary or isolated
// signer; every control-plane, CLI, and EE production file is scanned.
func TestControlPlaneHasNoAuditPrivateKeyOperations(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	repo, err := os.OpenRoot(root)
	if err != nil {
		t.Fatalf("open repository root: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	for _, tree := range []string{"cmd", "internal", "ee"} {
		err := fs.WalkDir(repo.FS(), tree, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if path == "internal/crypto" || path == "internal/signing" || path == "cmd/trstctl-signer" {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, err := repo.ReadFile(path)
			if err != nil {
				return err
			}
			for _, forbidden := range []string{
				"audit.LoadOrCreateSigningKey(",
				"jose.ParseRSASigningKey(",
				"jose.GenerateRSASigningKey(\"audit-export\"",
				"--audit-key",
			} {
				if strings.Contains(string(body), forbidden) {
					t.Errorf("%s contains forbidden control-plane audit private-key path %q", path, forbidden)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", tree, err)
		}
	}
}
