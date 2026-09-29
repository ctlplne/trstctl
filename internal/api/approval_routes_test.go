// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"strings"
	"testing"
)

// F262 ratchet: every route that records an approval or a denial counts toward
// dual control, so it must refuse a token one person minted for another subject.
// A new approval route that forgets the flag fails here.
func TestApprovalRoutesRefuseDelegatedTokens(t *testing.T) {
	a := New(nil, nil, nil)
	flagged := 0
	for _, r := range a.routes() {
		approvalShaped := strings.HasPrefix(r.opID, "approve") || strings.HasPrefix(r.opID, "deny") || r.opID == "decideAccessChangeRequest"
		if approvalShaped != r.approval {
			t.Errorf("route %s %s (%s): approval-shaped=%v, approval flag=%v", r.method, r.path, r.opID, approvalShaped, r.approval)
		}
		if !r.approval {
			continue
		}
		flagged++
		if r.method != http.MethodPost || r.perm == "" {
			t.Errorf("approval route %s %s (%s) must be an authenticated POST", r.method, r.path, r.opID)
		}
	}
	if flagged < 8 {
		t.Errorf("approval routes flagged = %d, want at least the 8 known approval and denial routes", flagged)
	}
}
