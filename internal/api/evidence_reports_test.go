// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"
)

// A252: a report reads two kinds of payload field and keeps each only in a
// form that cannot carry a name, free text or a secret: an outcome as one
// closed lowercase word, a subject as a UUID.
func TestEvidenceFieldsKeepOnlyClosedWordsAndUUIDs(t *testing.T) {
	for _, tc := range []struct {
		data             string
		outcome, subject string
	}{
		{`{"id":"2c30a5d3-bd31-45d1-8acd-96fdbfce0c84","status":"completed"}`, "completed", "2c30a5d3-bd31-45d1-8acd-96fdbfce0c84"},
		{`{"status":"Completed by alice@example.com","id":"alice@example.com"}`, "", ""},
		{`{"verdict":"matched","identity_id":"not-a-uuid","run_id":"441a572a-2020-40ad-90cb-943aa7485896"}`, "matched", "441a572a-2020-40ad-90cb-943aa7485896"},
		{`{"status":"","outcome":"rolled_back","certificate_id":"00000000-0000-0000-0000-000000000000"}`, "rolled_back", ""},
		{`{"status":{"sealed":"…"},"id":12}`, "", ""},
		{`not json`, "", ""},
		{`{"result":"` + strings.Repeat("a", 41) + `"}`, "", ""},
	} {
		outcome, subject := evidenceFields([]byte(tc.data))
		if outcome != tc.outcome || subject != tc.subject {
			t.Errorf("evidenceFields(%s) = %q, %q; want %q, %q", tc.data, outcome, subject, tc.outcome, tc.subject)
		}
	}
}

// Every template names its sections' event types, says what it cannot
// observe, and is a schedulable report type.
func TestEvidenceTemplatesAreCompleteAndSchedulable(t *testing.T) {
	for kind, tmpl := range evidenceTemplates {
		if tmpl.kind != kind || tmpl.title == "" || len(tmpl.sections) == 0 || len(tmpl.unobserved) == 0 {
			t.Errorf("%s: incomplete template %+v", kind, tmpl)
		}
		for _, s := range tmpl.sections {
			if s.name == "" || len(s.types)+len(s.prefixes) == 0 {
				t.Errorf("%s: section %+v reads nothing", kind, s)
			}
		}
		if !validComplianceReportType(kind) {
			t.Errorf("%s is not a schedulable report type", kind)
		}
	}
	if len(evidenceTemplates) != 5 {
		t.Fatalf("templates = %d, want 5", len(evidenceTemplates))
	}
}
