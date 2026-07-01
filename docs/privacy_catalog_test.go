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
		"approvals.actors",
		"profiles.created-by",
		"agents.name",
		"pam_sessions.subjects",
		"discovery_findings.triage",
		"notification_threshold_deliveries.subject",
		"incident_executions.operator-evidence",
		"oidc_prelogin.client-metadata",
		"nhi_access_reviews.actors",
		"access_change_requests.actors",
		"discovery_runs.requester",
		"notification_routing_policies.owner-contact",
		"remediation_playbook_runs.operator-evidence",
		"compliance_report_schedules.recipient",
		"incident_fleet_reissuance_runs.operator-evidence",
	}
	seen := privacyCatalogByID(t)
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

func TestPrivacyCatalogCoversServedSchemaPIIDenominator(t *testing.T) {
	required := []struct {
		id      string
		source  string
		markers []string
	}{
		{
			id:     "nhi_access_reviews.actors",
			source: "../internal/store/migrations/0056_nhi_access_reviews.sql",
			markers: []string{
				"reviewer_subject text",
				"requested_by     text",
				"decision_by            text",
				"decision_reason        text",
			},
		},
		{
			id:     "access_change_requests.actors",
			source: "../internal/store/migrations/0065_access_change_requests.sql",
			markers: []string{
				"requester_subject  text",
				"approver_subject       text",
				"reason                 text",
			},
		},
		{
			id:     "discovery_runs.requester",
			source: "../internal/store/migrations/0037_discovery_control_plane.sql",
			markers: []string{
				"requested_by text",
			},
		},
		{
			id:     "notification_routing_policies.owner-contact",
			source: "../internal/store/migrations/0062_notification_routing_policy_metadata.sql",
			markers: []string{
				"owner_ref text",
				"owner_email text",
			},
		},
		{
			id:     "remediation_playbook_runs.operator-evidence",
			source: "../internal/store/migrations/0059_remediation_playbook_runs.sql",
			markers: []string{
				"reason                 text",
				"evidence_refs          text[]",
				"created_by             text",
			},
		},
		{
			id:     "compliance_report_schedules.recipient",
			source: "../internal/store/migrations/0058_compliance_report_schedules.sql",
			markers: []string{
				"recipient_ref    text",
			},
		},
		{
			id:     "incident_fleet_reissuance_runs.operator-evidence",
			source: "../internal/store/migrations/0057_incident_fleet_reissuance_runs.sql",
			markers: []string{
				"reason                    text",
				"failed_targets            text[]",
				"evidence_bundle           text",
				"created_by                text",
			},
		},
	}

	seen := privacyCatalogByID(t)
	doc := read(t, "privacy-data-catalog.md")
	for _, req := range required {
		source := read(t, req.source)
		for _, marker := range req.markers {
			if !strings.Contains(source, marker) {
				t.Fatalf("%s no longer contains marker %q; update the privacy schema denominator", req.source, marker)
			}
		}
		entry, ok := seen[req.id]
		if !ok {
			t.Errorf("privacy catalog missing schema PII class %s", req.id)
			continue
		}
		if !strings.Contains(doc, "`"+req.id+"`") {
			t.Errorf("privacy-data-catalog.md missing schema PII class %s", req.id)
		}
		if !strings.Contains(entry.Erasure, "privacy.subject.erased") && !strings.Contains(entry.Erasure, "privacy.retention.enforced") {
			t.Errorf("%s erasure behavior does not name the durable privacy control: %q", req.id, entry.Erasure)
		}
	}
}

func privacyCatalogByID(t *testing.T) map[string]privacy.CatalogEntry {
	t.Helper()
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
	return seen
}
