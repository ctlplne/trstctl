// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/editionledger"
	"trstctl.com/trstctl/internal/license"
)

// A253: every edition and qualification statement resolves to the generated
// ledger. The ledger's JSON and page, and the marked blocks in README.md and
// docs/editions.md, must be exactly what `go run ./tools/editionledger`
// writes from internal/license and the feature map.
func TestEditionLedgerIsGeneratedAndCurrent(t *testing.T) {
	l, err := editionledger.Build()
	if err != nil {
		t.Fatal(err)
	}
	ledgerJSON, err := l.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, "editions-ledger.json"); got != string(ledgerJSON) {
		t.Errorf("docs/editions-ledger.json is out of date; run go run ./tools/editionledger")
	}
	if got := read(t, "editions-ledger.md"); got != l.Markdown() {
		t.Errorf("docs/editions-ledger.md is out of date; run go run ./tools/editionledger")
	}
	for page, blocks := range map[string][]string{"../README.md": {"readme-editions"}, "editions.md": {"editions-rights", "editions-buyer-matrix"}} {
		content := read(t, page)
		for _, block := range blocks {
			if !strings.Contains(content, "<!-- edition-ledger:begin "+block+" -->") {
				t.Errorf("%s lost its generated %s block", page, block)
			}
		}
		rendered, err := editionledger.ReplaceBlocks([]byte(content), l.Blocks())
		if err != nil || string(rendered) != content {
			t.Errorf("%s: a generated edition block drifted (%v); run go run ./tools/editionledger", page, err)
		}
	}
	// The License-Gated Features table keeps its product-line descriptions,
	// but each row's edition must be the one the license table grants.
	edition := map[string]string{"Enterprise": "enterprise", "Provider": "provider"}
	rows := regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\| (Enterprise|Provider) \\|").FindAllStringSubmatch(read(t, "editions.md"), -1)
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row[1]] = true
		for _, f := range l.Features {
			if f.Feature == row[1] && f.Tier != edition[row[2]] {
				t.Errorf("editions.md lists %s under %s; the license table grants it at %s", row[1], row[2], f.Tier)
			}
		}
	}
	for _, f := range l.Features {
		if !seen[f.Feature] {
			t.Errorf("editions.md's License-Gated Features table has no row for %s", f.Feature)
		}
	}
}

// openSourceClaim catches a sentence that calls trstctl, its core or its
// BUSL code open source. Third-party projects (SPIRE, agent frameworks) may be
// called open source; trstctl's core is source-available.
var openSourceClaim = regexp.MustCompile(`(?i)open[- ]source`)
var trstctlSubject = regexp.MustCompile(`(?i)\btrstctl\b|\bthe core\b|\bour core\b|\bBUSL\b|\bthis repository\b|\bthis project\b`)

func TestNoPageCallsTheBUSLCoreOpenSource(t *testing.T) {
	var pages []string
	for _, pattern := range []string{"../README.md", "../CONTRIBUTING.md", "*.md", "features/*.md"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, matches...)
	}
	for _, page := range pages {
		raw, err := os.ReadFile(page) // #nosec G304 -- test reads the repository's own documentation (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		for _, sentence := range regexp.MustCompile(`[.!?]\s+`).Split(string(raw), -1) {
			if openSourceClaim.MatchString(sentence) && trstctlSubject.MatchString(sentence) {
				t.Errorf("%s calls trstctl's code open source; the core is source-available under BUSL-1.1: %q", page, strings.TrimSpace(sentence))
			}
		}
	}
}

// thirdPartyEditions are other products whose own "Community" editions the
// docs describe: dynamic-secret databases and the containers proofs run on.
var thirdPartyEditions = regexp.MustCompile(`Couchbase|Vertica|SAP HANA|EJBCA|LocalStack`)

// TestFreeEditionIsNamedFromTheLedger: trstctl's no-license edition is named
// as the ledger names it (license.TierDisplay) in the docs and the console, so
// no page or screen calls it something the ledger does not list.
func TestFreeEditionIsNamedFromTheLedger(t *testing.T) {
	if got := license.TierDisplay(license.TierCommunity); got != "Free" {
		t.Fatalf("the ledger names the no-license edition %q; update this guard and the pages together", got)
	}
	var pages []string
	for _, pattern := range []string{"../README.md", "../CONTRIBUTING.md", "*.md", "*/*.md", "*/*/*.md", "../web/src/i18n/messages.ts"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, matches...)
	}
	community := regexp.MustCompile(`\bCommunity\b`)
	for _, page := range pages {
		raw, err := os.ReadFile(page) // #nosec G304 -- test reads the repository's own documentation and console catalog (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		for _, paragraph := range regexp.MustCompile(`\n\s*\n`).Split(string(raw), -1) {
			if community.MatchString(paragraph) && !thirdPartyEditions.MatchString(paragraph) {
				t.Errorf("%s names trstctl's no-license edition Community; the edition ledger calls it Free: %q", page,
					strings.TrimSpace(community.FindString(paragraph)+" … "+firstLine(paragraph, community)))
			}
		}
	}
}

func firstLine(paragraph string, re *regexp.Regexp) string {
	for _, line := range strings.Split(paragraph, "\n") {
		if re.MatchString(line) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}
