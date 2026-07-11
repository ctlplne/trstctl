// SPDX-License-Identifier: MPL-2.0

package acmekey

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalACMEAccountConstructorsHaveNoProductionCallers keeps the local-key
// helpers on the RFC 8555 client-test side of the repo. The shipped external-CA
// integration has exactly one public construction path, and it requires a
// DigestSigner backed by the isolated signer process.
func TestLocalACMEAccountConstructorsHaveNoProductionCallers(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	forbidden := [][]byte{
		[]byte("acmekey.NewClient("),
		[]byte("acmekey.NewRSAClient("),
		[]byte("letsencrypt.NewPlugin("),
		[]byte("letsencrypt.NewPluginWithHTTPClient("),
		[]byte("letsencrypt.NewPluginWithSolver("),
	}
	err = filepath.WalkDir(repo, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == "node_modules" || name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, symbol := range forbidden {
			if bytes.Contains(raw, symbol) {
				rel, _ := filepath.Rel(repo, path)
				t.Errorf("production file %s calls local ACME account constructor %s", rel, symbol)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
