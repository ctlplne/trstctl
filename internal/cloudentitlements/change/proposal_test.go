// SPDX-License-Identifier: BUSL-1.1
package change

import (
	"encoding/json"
	"testing"
	"testing/quick"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
)

func unusedPermission() assessment.Assessment {
	return assessment.Assessment{Evaluations: []assessment.Evaluation{{Check: assessment.Check{Action: "s3:GetObject", Resource: "arn:aws:s3:::owned/report"}, Result: awspolicy.Result{Decision: awspolicy.Allowed}, Unused: true, ActivityCoverage: awspolicy.Complete}}}
}
func TestCloudRestrictiveProposalNeverGrantsA264(t *testing.T) {
	raw, digest, err := RestrictivePolicy(unusedPermission(), 0)
	if err != nil || len(digest) != 64 {
		t.Fatal(err)
	}
	document, err := awspolicy.Parse("owned-deny", raw)
	if err != nil {
		t.Fatal(err)
	}
	check := func(n uint16) bool {
		action := "s3:GetObject"
		resource := "arn:aws:s3:::owned/report"
		if n%3 == 1 {
			action = "s3:PutObject"
		}
		if n%3 == 2 {
			resource += "-other"
		}
		request := awspolicy.Request{Principal: awspolicy.Principal{Kind: awspolicy.IAMUser, ARN: "arn:aws:iam::111122223333:user/workload", AccountID: "111122223333"}, Action: action, Resource: resource, ResourceAccountID: "111122223333", Context: awspolicy.Context{Complete: true}}
		result := awspolicy.Evaluate(request, awspolicy.Evidence{Identity: awspolicy.PolicySet{Coverage: awspolicy.Complete, Documents: []awspolicy.Document{document}}, Resource: awspolicy.PolicySet{Coverage: awspolicy.Absent}, Boundary: awspolicy.PolicySet{Coverage: awspolicy.Absent}, Session: awspolicy.PolicySet{Coverage: awspolicy.Absent}, SCPCoverage: awspolicy.Absent, RCPCoverage: awspolicy.Absent})
		return result.Decision != awspolicy.Allowed && (n%3 != 0 || result.Decision == awspolicy.ExplicitDeny)
	}
	if err := quick.Check(check, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*assessment.Evaluation){func(e *assessment.Evaluation) { e.Unused = false }, func(e *assessment.Evaluation) { e.ActivityCoverage = awspolicy.Unavailable }, func(e *assessment.Evaluation) { e.Result.Decision = awspolicy.Indeterminate }, func(e *assessment.Evaluation) { e.Check.Resource = "*" }, func(e *assessment.Evaluation) { e.Check.Action = "s3:*" }} {
		v := unusedPermission()
		mutate(&v.Evaluations[0])
		if _, _, err := RestrictivePolicy(v, 0); err == nil {
			t.Fatal("unproven or broad change accepted")
		}
	}
}
func FuzzCloudRestrictiveProposal(f *testing.F) {
	seed, _ := json.Marshal(unusedPermission())
	f.Add(seed, 0)
	f.Fuzz(func(t *testing.T, raw []byte, index int) {
		if len(raw) > 512<<10 {
			return
		}
		var value assessment.Assessment
		if json.Unmarshal(raw, &value) != nil {
			return
		}
		document, _, err := RestrictivePolicy(value, index)
		if err == nil {
			var out struct{ Statement []struct{ Effect string } }
			if json.Unmarshal(document, &out) != nil || len(out.Statement) != 1 || out.Statement[0].Effect != "Deny" {
				t.Fatal("proposal grants or rewrites permissions")
			}
		}
	})
}
