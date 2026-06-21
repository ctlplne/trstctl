package docs

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/privacy"
)

func TestPrivacyCatalogCoversSubjectErasurePIIFields(t *testing.T) {
	required := []string{
		"events.actor.subject",
		"events.data.subject-values",
		"owners.email",
		"tenant_members.subject",
		"api_tokens.subject",
		"identities.name-attributes",
		"certificates.subject-sans",
		"ssh_keys.comment-location",
		"attestations.evidence",
	}
	seen := map[string]privacy.CatalogEntry{}
	for _, entry := range privacy.Catalog() {
		if entry.ID == "" || entry.Location == "" || entry.Category == "" || entry.Purpose == "" || entry.RetentionClass == "" || entry.Erasure == "" || entry.Owner == "" {
			t.Fatalf("privacy catalog entry has blank required metadata: %+v", entry)
		}
		if _, ok := seen[entry.ID]; ok {
			t.Fatalf("duplicate privacy catalog id %q", entry.ID)
		}
		seen[entry.ID] = entry
	}
	doc := read(t, "privacy-data-catalog.md")
	for _, id := range required {
		if _, ok := seen[id]; !ok {
			t.Errorf("privacy catalog missing %s", id)
		}
		if !strings.Contains(doc, "`"+id+"`") {
			t.Errorf("privacy-data-catalog.md missing %s", id)
		}
	}
}
