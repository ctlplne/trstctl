// SPDX-License-Identifier: BUSL-1.1

package graph

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// TestPAMSessionApprovalStateIsNeverFalseForWhatIsUnknownG1L6: a PAM
// session's approval_recorded is "true" when its approval is known, recorded
// or derived from its activation (approval_link says which, and the
// approvers draw APPROVED edges either way), "false" only when the session
// recorded that it consumed none, and "unrecorded" for a session from before
// the link whose activation named none.
func TestPAMSessionApprovalStateIsNeverFalseForWhatIsUnknownG1L6(t *testing.T) {
	g := New()
	principals := principalIndex{}
	expires := time.Now().Add(time.Hour)
	for _, c := range []struct {
		id, approval, link string
		approvers          []string
		recorded, wantLink string
	}{
		{"s-recorded", "a-1", store.PAMApprovalLinkRecorded, []string{"rev-one"}, "true", "recorded"},
		{"s-derived", "a-2", store.PAMApprovalLinkDerived, []string{"rev-two"}, "true", "derived"},
		{"s-none", "", store.PAMApprovalLinkRecorded, nil, "false", "recorded"},
		{"s-unrecorded", "", "", nil, "unrecorded", "unrecorded"},
	} {
		addPAMSession(g, principals, store.PAMSessionAccess{ID: c.id, TargetType: "postgres", TargetID: "pg-main", Role: "reader",
			Status: "active", Subject: "workload", RequestedBy: "requester", ApprovalRequestID: c.approval, ApprovalLink: c.link,
			ExpiresAt: expires}, c.approvers)
		node, ok := g.Node(credentialID("pam", c.id))
		if !ok {
			t.Fatalf("%s: no node", c.id)
		}
		if node.Attrs["approval_recorded"] != c.recorded || node.Attrs["approval_link"] != c.wantLink {
			t.Fatalf("%s: approval_recorded %q approval_link %q, want %q %q", c.id, node.Attrs["approval_recorded"], node.Attrs["approval_link"], c.recorded, c.wantLink)
		}
		approved := 0
		for _, e := range g.Edges() {
			if e.Type == EdgeApproved && e.To == credentialID("pam", c.id) {
				approved++
			}
		}
		if approved != len(c.approvers) {
			t.Fatalf("%s: %d APPROVED edges, want %d", c.id, approved, len(c.approvers))
		}
	}
}
