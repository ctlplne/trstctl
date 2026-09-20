// SPDX-License-Identifier: BUSL-1.1

package webui_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// The embedded console must be built from the console source that is checked
// in (OPP-C02). `make web` stamps a digest of every console build input into
// SOURCE_DIGEST next to the embedded dist; this test recomputes it exactly as
// scripts/ci/web-source-digest.sh does — byte-wise sorted repo-relative paths,
// "<path>\n<sha256 hex>\n" per file, sha256 over the stream, dotfiles excluded —
// so a web/src change that was not followed by `make web` fails here (and in
// `make lint`) instead of shipping a stale embed behind a green gate.
func TestEmbeddedConsoleIsBuiltFromCheckedInSource(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, dir := range []string{"web/src", "web/public"} {
		root := filepath.Join(repo, dir)
		if _, statErr := os.Stat(root); statErr != nil {
			continue
		}
		walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || strings.HasPrefix(d.Name(), ".") {
				return nil
			}
			rel, relErr := filepath.Rel(repo, p)
			if relErr != nil {
				return relErr
			}
			files = append(files, filepath.ToSlash(rel))
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", dir, walkErr)
		}
	}
	for _, f := range []string{"web/index.html", "web/package.json", "web/package-lock.json", "web/vite.config.ts", "web/tsconfig.json", "web/tsconfig.build.json"} {
		if _, statErr := os.Stat(filepath.Join(repo, f)); statErr == nil {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	// Hashing goes through the sanctioned internal/crypto boundary (AN-3).
	var stream bytes.Buffer
	for _, f := range files {
		raw, readErr := os.ReadFile(filepath.Join(repo, f)) // #nosec G304 -- console build inputs inside the repository (CWE-22)
		if readErr != nil {
			t.Fatalf("read %s: %v", f, readErr)
		}
		fmt.Fprintf(&stream, "%s\n%s\n", f, crypto.SHA256Hex(raw))
	}
	have := crypto.SHA256Hex(stream.Bytes())
	stamp, readErr := os.ReadFile(filepath.Join(repo, "internal/webui/SOURCE_DIGEST")) // #nosec G304 -- fixed repository path (CWE-22)
	if readErr != nil {
		t.Fatalf("SOURCE_DIGEST is missing: run `make web` to rebuild the console and stamp its source digest (OPP-C02): %v", readErr)
	}
	want := strings.TrimSpace(string(stamp))
	if have != want {
		t.Fatalf("embedded console is stale: console source digest %s != stamped %s (OPP-C02). web/src or another console build input changed without regenerating internal/webui/dist; run `make web` and commit dist + SOURCE_DIGEST.", have, want)
	}
}
