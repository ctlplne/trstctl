// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"strings"
	"testing"
)

func TestCAPreservingJourneyLeadsBeforeOptionalCAReplacement(t *testing.T) {
	preserve := read(t, "journeys/preserve-existing-ca.md")
	for _, want := range []string{
		"# Keep your existing CA",
		"trstctl does not replace your CA",
		"configured external CA",
		"never silently falls back",
		"effect-free preview",
		"operator prerequisites",
		"second renewal",
		"listener fingerprint",
		"alert acknowledgment",
	} {
		if !strings.Contains(preserve, want) {
			t.Errorf("CA-preserving journey is missing cold-reader contract %q", want)
		}
	}

	replace := read(t, "journeys/migrate-from-existing-ca.md")
	for _, want := range []string{
		"# Replace your existing CA (optional)",
		"You do not need this journey to use trstctl",
		"Keep your existing CA",
		"preserve-existing-ca.md",
	} {
		if !strings.Contains(replace, want) {
			t.Errorf("optional CA-replacement journey is missing boundary %q", want)
		}
	}
	if strings.Contains(replace, "# Migrate from your existing CA") {
		t.Error("CA-replacement journey still presents authority replacement as the default migration path")
	}

	readme := read(t, "../README.md")
	preserveLink := "docs/journeys/preserve-existing-ca.md"
	replaceLink := "docs/journeys/migrate-from-existing-ca.md"
	if !strings.Contains(readme, preserveLink) || !strings.Contains(readme, replaceLink) {
		t.Fatal("README must link both the CA-preserving and optional CA-replacement journeys")
	}
	if strings.Index(readme, preserveLink) > strings.Index(readme, replaceLink) {
		t.Error("README must lead with CA preservation before optional CA replacement")
	}

	nav := read(t, "../mkdocs.yml")
	for _, want := range []string{
		"Keep your existing CA: journeys/preserve-existing-ca.md",
		"Replace your existing CA (optional): journeys/migrate-from-existing-ca.md",
	} {
		if !strings.Contains(nav, want) {
			t.Errorf("docs navigation is missing %q", want)
		}
	}
}
