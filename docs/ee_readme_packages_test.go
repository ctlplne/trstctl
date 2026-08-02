// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ---- DOCS-010: the ee/ README package listing equals `ls ee/` ------------------
//
// The audit found ee/README.md still documenting `ee/fleet` — a package the
// CHANGELOG had already deleted — both as a listing bullet and inside the served
// remediation sentence, under a heading that literally captions the list as
// `ls ee/`. Anyone who ran the command in the caption got a different answer than
// the page gave. This guard binds the page to the directory in both directions so
// a package add or delete cannot silently desync it again.

// eeReadmeProseOnlyDirs are ee/ subdirectories the README documents in prose rather
// than as a package bullet, because they hold no Go package. Each entry is an
// exemption from the reverse half below, so this map must stay short and every
// entry must carry the reason it is not a package.
var eeReadmeProseOnlyDirs = map[string]string{
	"docs": "PCAS reference material behind the AN-9 fence, not a Go package; carried by the ee/docs/ paragraph",
}

// eeBacktickPath matches a backticked span in ee/README.md that names an ee/ path,
// e.g. `ee/incident` or `ee/docs/`. The span must START with ee/, so the caption's
// `ls ee/`, the bare `ee/`, and the import path `trstctl.com/trstctl/ee` are all
// correctly left alone.
var eeBacktickPath = regexp.MustCompile("`ee/([A-Za-z0-9_.-]+)/?`")

// eePackageBullet matches the listing bullets themselves, e.g.
// "- `ee/incident`: credential-compromise workflow library."
var eePackageBullet = regexp.MustCompile("(?m)^- `ee/([A-Za-z0-9_.-]+)`:")

// TestEEReadmeListingMatchesTree is the DOCS-010 reality test for ee/README.md:
// nothing it names under ee/ may be absent from the tree, and nothing in the tree
// may be absent from it.
func TestEEReadmeListingMatchesTree(t *testing.T) {
	const readmeRel = "../ee/README.md"
	const caption = "## Packages (`ls ee/`)"

	body := read(t, readmeRel)

	// The caption is the promise this guard defends: it tells the reader the list
	// below is what `ls ee/` prints. If it is reworded, the premise changed and a
	// human must revisit the guard rather than let it quietly assert nothing.
	if !strings.Contains(body, caption) {
		t.Fatalf("DOCS-010: %s no longer carries the %q heading; the listing no longer claims to equal `ls ee/`, so revisit this guard", readmeRel, caption)
	}

	entries, err := os.ReadDir(filepath.FromSlash("../ee"))
	if err != nil {
		t.Fatalf("DOCS-010: read ee/: %v", err)
	}
	onDisk := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			onDisk[e.Name()] = true
		}
	}
	if len(onDisk) == 0 {
		t.Fatal("DOCS-010: found no subdirectories under ee/; revisit this guard")
	}

	// Forward half, whole file: every backticked ee/<name> the README mentions —
	// bullet, prose, or parenthetical — must name a directory that exists. Scanning
	// the whole file rather than just the listing is what catches the second
	// ee/fleet mention, the one inside the served-remediation sentence.
	for _, m := range eeBacktickPath.FindAllStringSubmatch(body, -1) {
		if !onDisk[m[1]] {
			t.Errorf("DOCS-010: %s documents `ee/%s` but ee/%s does not exist; the page under %q must match the tree", readmeRel, m[1], m[1], caption)
		}
	}

	// Reverse half: every real ee/ subdirectory except the prose-only exemptions
	// must have its own bullet, so a newly added package cannot land undocumented.
	documented := map[string]bool{}
	for _, m := range eePackageBullet.FindAllStringSubmatch(body, -1) {
		documented[m[1]] = true
	}
	if len(documented) == 0 {
		t.Fatalf("DOCS-010: parsed no \"- `ee/<pkg>`:\" bullets out of %s; the listing format changed, so revisit this guard", readmeRel)
	}
	var missing []string
	for name := range onDisk {
		if documented[name] {
			continue
		}
		if reason, exempt := eeReadmeProseOnlyDirs[name]; exempt {
			// Exempt from the bullets, not from being mentioned at all.
			if !strings.Contains(body, "ee/"+name) {
				t.Errorf("DOCS-010: ee/%s is exempt from the package bullets (%s) but %s no longer mentions it at all", name, reason, readmeRel)
			}
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("DOCS-010: ee/ contains %v with no \"- `ee/<pkg>`:\" bullet in %s; every ee/ package must be documented under %q", missing, readmeRel, caption)
	}
}
