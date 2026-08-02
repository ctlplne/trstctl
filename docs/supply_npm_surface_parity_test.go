// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- SUPPLY-106: every npm dependency surface is locked, audited, and updated ----

// npmSurfaceSkipDirs are directory names that never hold a first-party npm
// dependency surface: installed trees, build output, and tool caches. Any other
// directory carrying a package.json is a real surface and must be covered.
var npmSurfaceSkipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"coverage":     true,
}

// TestSupply105NpmAuditSurfacesMatchTrackedPackageJSON locks SUPPLY-106: the set of
// npm dependency surfaces the supply-chain wrapper audits must EQUAL the set of
// first-party package.json trees in the repository; every one of those trees must
// carry a committed package-lock.json; and every one must have a Dependabot npm
// entry. ELI5: a dependency tree nobody scans is not "clean", it is unexamined —
// and an unlocked tree cannot be scanned reproducibly at all, because the resolved
// versions differ per install.
//
// The existing SUPPLY-005 guard asserts that the two surfaces it knows about are
// present. That is a presence check, not a parity check, so it would not notice a
// third or fourth package.json appearing with no lockfile and no scanner. This
// guard closes that: it enumerates surfaces from the tree, not from a hand list.
func TestSupply105NpmAuditSurfacesMatchTrackedPackageJSON(t *testing.T) {
	const root = ".."

	var surfaces []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if strings.HasPrefix(name, ".") || npmSurfaceSkipDirs[name] {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" {
			return nil
		}
		rel, relErr := filepath.Rel(root, filepath.Dir(path))
		if relErr != nil {
			return relErr
		}
		surfaces = append(surfaces, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("SUPPLY-106: walk repository for package.json: %v", err)
	}
	if len(surfaces) < 3 {
		t.Fatalf("SUPPLY-106: found only %d npm dependency surfaces (%v); the repository has at least three (web, TypeScript SDK, Pulumi IaC), so this walk is wrong — revisit this guard", len(surfaces), surfaces)
	}

	checker := read(t, "../scripts/ci/npm-audit-dependency-surfaces.sh")
	dependabot := read(t, "../.github/dependabot.yml")

	for _, dir := range surfaces {
		if _, statErr := os.Stat(filepath.Join(root, filepath.FromSlash(dir), "package-lock.json")); statErr != nil {
			t.Errorf("SUPPLY-106: %s/package.json has no committed package-lock.json (%v); an unlocked tree resolves differently on every install, so it cannot be audited reproducibly", dir, statErr)
		}
		// Anchor on the `${repo}/<dir>` prefix the wrapper actually builds, not on the
		// bare directory name: a bare "web" would match almost any line and make this
		// assertion vacuous.
		if !strings.Contains(checker, "${repo}/"+dir) {
			t.Errorf("SUPPLY-106: scripts/ci/npm-audit-dependency-surfaces.sh has no ${repo}/%s prefix; that npm dependency tree is scanned by nothing", dir)
		}
		if !strings.Contains(dependabot, `directory: "/`+dir+`"`) {
			t.Errorf("SUPPLY-106: .github/dependabot.yml has no npm entry with directory: \"/%s\"; that npm dependency tree gets no update PRs", dir)
		}
	}

	// Naming a prefix is not auditing it. Require one audit_lock invocation per
	// surface so a prefix variable cannot be declared and then never used.
	if audited := strings.Count(checker, "\naudit_lock \""); audited != len(surfaces) {
		t.Errorf("SUPPLY-106: scripts/ci/npm-audit-dependency-surfaces.sh makes %d audit_lock calls but the repository has %d npm dependency surfaces (%v); every surface must be handed to audit_lock", audited, len(surfaces), surfaces)
	}
}
