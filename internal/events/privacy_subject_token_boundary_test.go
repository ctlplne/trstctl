// SPDX-License-Identifier: MPL-2.0

package events

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/privacyref"
)

// TestSubjectTokenErasesHyphenJoinedIdentity is the regression guard for the
// erasure defect that shipped on main: '-' was treated as a rune that sits
// INSIDE a subject token, so an identity joined to a prefix by a hyphen had no
// left-hand token boundary and was never matched. A data-subject erasure then
// reported success while leaving the identity byte-exact in the event log —
// permanently, because AN-2 makes that log append-only.
//
// The shape below is not hypothetical: provider tenant slugs are built as
// "customer-" + the operator's email address.
func TestSubjectTokenErasesHyphenJoinedIdentity(t *testing.T) {
	const (
		eventType = "privacy.policy.subject-token-boundary.test"
		tenantID  = "tenant-a"
		subject   = "operator@example.test"
	)
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/slug", Mode: PrivacyFieldSubjectToken},
		{Path: "/name", Mode: PrivacyFieldSubjectToken},
	}}); err != nil {
		t.Fatal(err)
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef(tenantID, subject))

	for _, tc := range []struct {
		name    string
		payload string
		want    string
	}{
		// The defect: a hyphen prefix. Erasure silently retained the identity.
		{"hyphen prefix", `{"slug":"customer-operator@example.test","name":"x"}`, "customer-" + placeholder},
		// A hyphen suffix is the same boundary in the other direction.
		{"hyphen suffix", `{"slug":"operator@example.test-primary","name":"x"}`, placeholder + "-primary"},
		// Already worked (space boundary) — kept so a fix cannot regress it.
		{"space separated", `{"slug":"Customer operator@example.test","name":"x"}`, "Customer " + placeholder},
		// Already worked (colon boundary) — the documented delegate:<subject> form.
		{"colon separated", `{"slug":"delegate:operator@example.test","name":"x"}`, "delegate:" + placeholder},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, changed, err := PseudonymizeEventDataForSubject([]byte(tc.payload), tenantID, subject, eventType, 1)
			if err != nil {
				t.Fatalf("erasure failed: %v", err)
			}
			if !changed {
				t.Fatal("erasure reported no change")
			}
			if strings.Contains(string(out), subject) {
				t.Fatalf("erasure retained the subject: %s", out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("erasure = %s, want it to contain %q", out, tc.want)
			}
		})
	}
}

// TestSubjectTokenLeavesUnrelatedIdentifiersIntact keeps the boundary rule
// honest in the other direction: '.', '@' and '_' remain token-INTERNAL, so a
// short subject must not chew a fragment out of an unrelated value. Without
// this, "fixing" the hyphen case by treating every punctuation mark as a
// separator would corrupt opaque identifiers.
func TestSubjectTokenLeavesUnrelatedIdentifiersIntact(t *testing.T) {
	const (
		eventType = "privacy.policy.subject-token-narrow.test"
		tenantID  = "tenant-a"
		subject   = "a"
	)
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/destination", Mode: PrivacyFieldSubjectToken},
	}}); err != nil {
		t.Fatal(err)
	}
	// "ca.issue" must survive a one-character subject "a": '.' is internal, and
	// the 'a' in "ca" is preceded by a letter, so neither position is a token.
	out, _, err := PseudonymizeEventDataForSubject(
		[]byte(`{"destination":"ca.issue"}`), tenantID, subject, eventType, 1,
	)
	if err != nil {
		t.Fatalf("erasure failed: %v", err)
	}
	if !strings.Contains(string(out), `"destination":"ca.issue"`) {
		t.Fatalf("short subject corrupted an unrelated identifier: %s", out)
	}
}
