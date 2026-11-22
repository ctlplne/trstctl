// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

// CR-001: a frozen evaluation never binds a rule to a request its own author
// made. A recorded witness that does is refused instead of replayed, so a
// retry cannot carry a self-approval through the frozen record.
func TestCanonicalAutoEvaluationNeverBindsARuleToItsAuthorCR001(t *testing.T) {
	for _, tc := range []struct {
		author, requester string
		want              bool
	}{{"approver", "user", true}, {"user", "user", false}, {"user", "bundle-run:user", false}} {
		source, req, err := a261CanonicalEvaluation()
		if err != nil {
			t.Fatal(err)
		}
		var v projections.PAMAutoApprovalEvaluated
		if err := json.Unmarshal(source.Data, &v); err != nil {
			t.Fatal(err)
		}
		v.Rule.SavedBy = tc.author
		v.Requester = tc.requester
		source.Actor.Subject = tc.requester
		if source.Data, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
		_, err = pamCanonicalAutoEvaluation(source, "tenant", "event", "request", req, tc.requester, "digest", a261ReviewTTL)
		if got := err == nil; got != tc.want {
			t.Errorf("frozen rule written by %q for a request by %q: accepted=%v, want %v (%v)", tc.author, tc.requester, got, tc.want, err)
		}
	}
}

// CR-001: a matching rule approves a request alone only where the deployment
// says so (pam.auto_approval_alone); otherwise its approval is one of the
// request's required approvals and reviewers give the rest.
func TestAutoApprovalAloneIsADeploymentChoiceCR001(t *testing.T) {
	t.Parallel()
	if pamFromConfig(config.PAM{Enabled: true}).AutoApprovalAlone {
		t.Fatal("a rule approves alone by default; the deployment must opt in")
	}
	if !pamFromConfig(config.PAM{Enabled: true, AutoApprovalAlone: true}).AutoApprovalAlone {
		t.Fatal("pam.auto_approval_alone does not reach the broker")
	}
}
