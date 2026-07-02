package privacy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivacyCatalogCoversSchemaAndRuntimePII(t *testing.T) {
	required := []struct {
		id      string
		source  string
		markers []string
	}{
		{
			id:     "pam_sessions.subjects",
			source: "../store/migrations/0049_pam_sessions.sql",
			markers: []string{
				"subject         text NOT NULL",
				"requested_by    text NOT NULL",
				"reason          text NOT NULL",
			},
		},
		{
			id:     "discovery_findings.triage",
			source: "../store/migrations/0051_discovery_finding_triage.sql",
			markers: []string{
				"triage_actor text NOT NULL",
				"triage_reason text NOT NULL",
			},
		},
		{
			id:     "discovery_sources.config",
			source: "../store/migrations/0037_discovery_control_plane.sql",
			markers: []string{
				"config     jsonb NOT NULL DEFAULT '{}'",
			},
		},
		{
			id:     "discovery_findings.metadata",
			source: "../store/migrations/0037_discovery_control_plane.sql",
			markers: []string{
				"metadata      jsonb NOT NULL DEFAULT '{}'",
			},
		},
		{
			id:     "notification_threshold_deliveries.subject",
			source: "../store/migrations/0053_notification_threshold_deliveries.sql",
			markers: []string{
				"subject        text NOT NULL",
				"channel        text NOT NULL",
			},
		},
		{
			id:     "incident_executions.operator-evidence",
			source: "../store/migrations/0041_incident_executions.sql",
			markers: []string{
				"reason                   text NOT NULL",
				"evidence_bundle          text NOT NULL",
				"created_by               text NOT NULL",
			},
		},
		{
			id:     "oidc_prelogin.client-metadata",
			source: "../api/oidc_prelogin.go",
			markers: []string{
				"ClientIP     string",
				"UserAgent    string",
			},
		},
	}

	seen := map[string]CatalogEntry{}
	for _, entry := range Catalog() {
		if entry.ID == "" || entry.Location == "" || entry.Category == "" || entry.Purpose == "" || entry.RetentionClass == "" || entry.Erasure == "" || entry.Owner == "" {
			t.Fatalf("privacy catalog entry has blank required metadata: %+v", entry)
		}
		if _, ok := seen[entry.ID]; ok {
			t.Fatalf("duplicate privacy catalog id %q", entry.ID)
		}
		seen[entry.ID] = entry
	}
	doc := readPrivacyDoc(t)
	for _, req := range required {
		source := readSource(t, req.source)
		for _, marker := range req.markers {
			if !strings.Contains(source, marker) {
				t.Fatalf("%s no longer contains marker %q; update the privacy schema coverage denominator", req.source, marker)
			}
		}
		entry, ok := seen[req.id]
		if !ok {
			t.Errorf("privacy catalog missing schema/runtime PII class %s", req.id)
			continue
		}
		if !strings.Contains(doc, "`"+req.id+"`") {
			t.Errorf("privacy-data-catalog.md missing schema/runtime PII class %s", req.id)
		}
		if !strings.Contains(entry.Erasure, "privacy.subject.erased") && !strings.Contains(entry.Erasure, "privacy.retention.enforced") && !strings.Contains(entry.Erasure, "TTL") {
			t.Errorf("%s erasure behavior does not name the erasure/retention control: %q", req.id, entry.Erasure)
		}
	}
}

func readSource(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func readPrivacyDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash("../../docs/privacy-data-catalog.md"))
	if err != nil {
		t.Fatalf("read privacy-data-catalog.md: %v", err)
	}
	return string(b)
}
