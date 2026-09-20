// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"regexp"
	"strings"
	"testing"
)

// The console's navigation labels are the canonical names of the six tools. Every
// entry surface a cold reader meets first — README, docs home, product map — must use
// exactly those names, so what they read is what they click (DP2-003).
func TestEntrySurfacesUseTheConsoleToolLabels(t *testing.T) {
	catalog := read(t, "../web/src/i18n/messages.ts")
	labels := map[string]string{}
	for _, key := range []string{"nav.space.discovery", "nav.module.certificates", "nav.space.workload", "nav.module.secrets", "nav.space.posture", "nav.space.platform"} {
		m := regexp.MustCompile(`(?s)"` + regexp.QuoteMeta(key) + `":\s*\{\s*defaultMessage:\s*"([^"]+)"`).FindStringSubmatch(catalog)
		if m == nil {
			t.Fatalf("console message catalog no longer defines %s; revisit this guard", key)
		}
		labels[key] = m[1]
	}
	for _, surface := range []string{"../README.md", "index.md", "product-map.md"} {
		body := read(t, surface)
		for key, label := range labels {
			if !strings.Contains(body, label) {
				t.Errorf("%s does not use the console label %q (%s); entry surfaces must match the navigation registry", surface, label, key)
			}
		}
	}
	// Workspace titles stay explained (TestWorkspaceMentalModelIsDocumented), but
	// never as the tool's heading name on its own.
	for _, stale := range []string{"### Certificate Lifecycle —", "### Machine & Workload Trust —", "### Secrets & Access —", "### Trust Operations —"} {
		if strings.Contains(read(t, "product-map.md"), stale) {
			t.Errorf("product-map.md still heads a tool with its workspace title only %q", stale)
		}
	}
}

// The CA-preserving journey is the flagship; wherever the CA-replacing journey is
// offered, the preserving one must be offered too, and first (DP2-004).
func TestKeepYourCAIsOfferedWhereverReplaceYourCAIs(t *testing.T) {
	for _, f := range []string{"index.md", "product-map.md", "getting-started.md"} {
		body := read(t, f)
		replace := strings.Index(body, "journeys/migrate-from-existing-ca.md")
		if replace < 0 {
			continue
		}
		keep := strings.Index(body, "journeys/preserve-existing-ca.md")
		if keep < 0 || keep > replace {
			t.Errorf("%s offers the CA-replacing journey without offering Keep your existing CA before it", f)
		}
	}
}

// The rendered site must contain reader-facing pages only (DP2-009).
func TestRenderedSiteExcludesTestSourcesAndFixtures(t *testing.T) {
	cfg := read(t, "../mkdocs.yml")
	for _, want := range []string{"exclude_docs:", "*_test.go", "*_test.mjs", "journeys/census-requirements.json", "journeys/served-census.json"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("mkdocs.yml must exclude %q from the rendered site", want)
		}
	}
}

// Core nouns need one findable definition (DP2-001, DP2-005).
func TestGlossaryDefinesTheNounsTheConsoleUses(t *testing.T) {
	glossary := read(t, "glossary.md")
	for _, heading := range []string{"### Issuer", "### Machine identity", "### Agent (trstctl Edge runtime)", "### Owner", "### Destination / deployment target"} {
		if !strings.Contains(glossary, heading) {
			t.Errorf("glossary.md lacks %q", heading)
		}
	}
	if strings.Contains(glossary, "### trstctl Edge (agent runtime)") {
		t.Error("glossary.md heads the runtime entry with the packaging name; the product name is agent (DP2-005)")
	}
}
