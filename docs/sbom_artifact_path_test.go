// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"strings"
	"testing"
)

// ---- SUPPLY-105: the module SBOM lands in an ignored build directory -----------

// TestSupply105ModuleSBOMWritesUnderIgnoredBuildDir locks SUPPLY-105: `make sbom`
// must write the CycloneDX module SBOM under dist/release-evidence/, never at the
// repository root.
//
// Before this guard the target ran `-output sbom.module.cyclonedx.json`, so the
// generated file landed at the repo root and showed as `??` in `git status`:
// untracked AND unignored. A bulk `git add -A` would stage a machine-local,
// timestamped dependency dump as if it were reviewed source. The fix puts it beside
// the other generated release receipts (`make license-audit` already writes
// dist/release-evidence/license-audit.json) instead of adding a second .gitignore
// exception: /dist/ is already ignored, and one convention beats one convention
// plus one special case.
func TestSupply105ModuleSBOMWritesUnderIgnoredBuildDir(t *testing.T) {
	const artifact = "dist/release-evidence/sbom.module.cyclonedx.json"

	mk := read(t, "../Makefile")
	requireAllContained(t, "SUPPLY-105", "Makefile", mk,
		".PHONY: sbom",
		"@mkdir -p dist/release-evidence",
		"$(CYCLONEDX_GOMOD) mod -json -licenses -output "+artifact,
		"@test -s "+artifact,
	)
	// A "contains the new path" check alone would still pass if someone re-added a
	// second write at the root, so assert the bare root path is gone as well.
	for _, forbidden := range []string{
		"-output sbom.module.cyclonedx.json",
		"@test -s sbom.module.cyclonedx.json",
	} {
		if strings.Contains(mk, forbidden) {
			t.Errorf("SUPPLY-105: Makefile still writes the module SBOM to the repo root (%q); at the root it is untracked AND unignored, so a bulk stage sweeps it into a commit", forbidden)
		}
	}

	ci := read(t, "../.github/workflows/ci.yml")
	requireAllContained(t, "SUPPLY-105", "ci.yml", ci,
		"run: make sbom",
		"          name: sbom-module-cyclonedx\n          path: "+artifact+"\n          if-no-files-found: error\n",
	)

	// Relocating the file only helps because /dist/ is ignored; if that line ever
	// goes away the artifact becomes stageable again from its new home.
	if !strings.Contains(read(t, "../.gitignore"), "\n/dist/\n") {
		t.Error("SUPPLY-105: .gitignore must keep /dist/ ignored, otherwise the module SBOM is stageable again from dist/release-evidence/")
	}

	if !strings.Contains(read(t, "supply-chain.md"), artifact) {
		t.Errorf("SUPPLY-105: docs/supply-chain.md must name the real module SBOM path %q", artifact)
	}
}
