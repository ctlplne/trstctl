// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// placeholderSelfDescriptions are the phrases a package doc uses to tell a godoc
// reader that nothing is built here yet. TestProtocolDocsNoLongerClaimPlaceholders
// banned them for three protocol files (INTEROP-008); the same stale prose
// survived in other shipped subsystems, so this list is the class rather than a
// file list.
var placeholderSelfDescriptions = []string{
	"reserves the package",
	"implementation begins",
	"implementation matures in sprint",
}

// skippedPackageDocScanDirs are directories whose Go files are not this
// repository's own package documentation: dependency trees, and the analyzer
// fixture trees under testdata/ where stub prose is the point of the fixture.
var skippedPackageDocScanDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	"testdata":     true,
}

// TestNoPackageDocDeclaresItselfAPlaceholder widens INTEROP-008 from a hardcoded
// three-file list to every non-test Go file in the tree. ELI5: a package that
// ships inside the binaries must not tell a godoc reader it is an empty
// reservation waiting for a future sprint. Fixing the prose one package at a time
// is what let the claim survive in internal/agent, internal/graph and
// internal/policy after the protocol packages were cleaned up, so the sweep is
// repository-wide and any newly added placeholder sentence fails here.
func TestNoPackageDocDeclaresItselfAPlaceholder(t *testing.T) {
	const root = ".."
	scanned := 0
	err := filepath.WalkDir(filepath.FromSlash(root), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == filepath.FromSlash(root) {
				return nil
			}
			if name := d.Name(); strings.HasPrefix(name, ".") || skippedPackageDocScanDirs[name] {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		scanned++
		src := strings.ToLower(read(t, path))
		for _, phrase := range placeholderSelfDescriptions {
			if strings.Contains(src, phrase) {
				t.Errorf("%s calls a shipped package a placeholder (%q); state what the package actually does and keep sprint IDs out of published godoc (INTEROP-008)", path, phrase)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s for package-doc placeholders: %v", root, err)
	}
	// Non-vacuity: if the tree moves or the skip list over-prunes, this guard must
	// fail loudly instead of silently scanning nothing.
	if scanned < 1000 {
		t.Fatalf("scanned only %d non-test Go files under %s; the package-doc placeholder sweep no longer covers the repository (expected more than 1000)", scanned, root)
	}
}
