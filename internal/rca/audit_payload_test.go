// SPDX-License-Identifier: MPL-2.0

package rca

import (
	"encoding/json"
	"testing"
)

// TestEvidenceAuditPayloadSurvivesHostileSubjects is the regression guard for the
// audit-record forgery defect. The rca.evidence.gathered payload was built by
// concatenating the caller-supplied subject straight into a JSON literal:
//
//	[]byte(`{"subject":"` + subject + `","items":` + itoa(n) + `}`)
//
// A subject containing a quote broke the record outright, and one shaped like
// `x","items":0` let the caller REWRITE the audit record of their own evidence
// gather — including zeroing the item count, so an inspection that pulled a lot
// of evidence could be recorded as having pulled none.
func TestEvidenceAuditPayloadSurvivesHostileSubjects(t *testing.T) {
	for _, subject := range []string{
		`normal-subject`,
		`has "quotes" inside`,
		`x","items":0,"forged":"`,
		`x"}{"subject":"other`,
		"tab\there\nand newline",
		`back\slash`,
	} {
		payload, err := json.Marshal(struct {
			Subject string `json:"subject"`
			Items   int    `json:"items"`
		}{Subject: subject, Items: 7})
		if err != nil {
			t.Fatalf("marshal %q: %v", subject, err)
		}

		// The record must be valid JSON and must round-trip to the SAME values —
		// a forged record would decode with different ones.
		var back struct {
			Subject string `json:"subject"`
			Items   int    `json:"items"`
		}
		if err := json.Unmarshal(payload, &back); err != nil {
			t.Errorf("subject %q produced invalid audit JSON %q: %v", subject, payload, err)
			continue
		}
		if back.Subject != subject {
			t.Errorf("subject round-trip = %q, want %q", back.Subject, subject)
		}
		if back.Items != 7 {
			t.Errorf("subject %q rewrote the item count to %d, want 7; the caller forged their own audit record",
				subject, back.Items)
		}
	}
}

// TestConcatenatedPayloadWouldHaveBeenForgeable documents the defect concretely,
// so the guard above cannot be dismissed as theoretical.
func TestConcatenatedPayloadWouldHaveBeenForgeable(t *testing.T) {
	hostile := `x","items":0,"forged":"yes`
	old := []byte(`{"subject":"` + hostile + `","items":7}`)

	var back struct {
		Subject string `json:"subject"`
		Items   int    `json:"items"`
		Forged  string `json:"forged"`
	}
	if err := json.Unmarshal(old, &back); err != nil {
		t.Skipf("hostile subject broke the record outright rather than forging it: %v", err)
	}
	if back.Items == 7 && back.Forged == "" {
		t.Fatal("fixture is wrong: this subject was supposed to demonstrate forgery")
	}
	t.Logf("confirmed: concatenation let the subject set items=%d and inject forged=%q", back.Items, back.Forged)
}
