// SPDX-License-Identifier: BUSL-1.1
package assessment

import (
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
)

func TestAWSActivityUnusedStaleAndEscalationA264(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	arn := "arn:aws:iam::111122223333:user/workload"
	policy, err := awspolicy.Parse("native-policy", []byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","iam:PutUserPolicy"],"Resource":"*"}}`))
	if err != nil {
		t.Fatal(err)
	}
	identity := awsiam.Identity{Principal: awspolicy.Principal{Kind: awspolicy.IAMUser, ARN: arn, AccountID: "111122223333"}, Name: "workload", Evidence: awspolicy.Evidence{Identity: awspolicy.PolicySet{Coverage: awspolicy.Complete, Documents: []awspolicy.Document{policy}}, Boundary: awspolicy.PolicySet{Coverage: awspolicy.Absent}, Session: awspolicy.PolicySet{Coverage: awspolicy.Absent}, Resource: awspolicy.PolicySet{Coverage: awspolicy.Unavailable}, SCPCoverage: awspolicy.Unavailable, RCPCoverage: awspolicy.Unavailable}, Keys: []awsiam.Key{{ID: "AKIAEXAMPLE", Status: "Active", Created: now.Add(-100 * 24 * time.Hour), LastUseCoverage: awspolicy.Complete}}}
	resource := "arn:aws:s3:::owned/report"
	input := Input{Checks: []Check{{PrincipalARN: arn, Action: "s3:GetObject", Resource: resource, ResourceAccountID: "111122223333", Context: awspolicy.Context{Complete: true}}, {PrincipalARN: arn, Action: "s3:PutObject", Resource: resource, ResourceAccountID: "111122223333", Context: awspolicy.Context{Complete: true}}, {PrincipalARN: arn, Action: "iam:PutUserPolicy", Resource: arn, ResourceAccountID: "111122223333", Context: awspolicy.Context{Complete: true}}}, Supplemental: []Supplemental{{PrincipalARN: arn, SourceRef: "recorded:organization-fixture", Resource: resource, ResourceAccountID: "111122223333", ResourcePolicies: PolicySet{Coverage: awspolicy.Absent}, SCPCoverage: awspolicy.Absent, RCPCoverage: awspolicy.Absent}, {PrincipalARN: arn, SourceRef: "recorded:organization-fixture", Resource: arn, ResourceAccountID: "111122223333", ResourcePolicies: PolicySet{Coverage: awspolicy.Absent}, SCPCoverage: awspolicy.Absent, RCPCoverage: awspolicy.Absent}}, Activity: ActivityEvidence{SourceRef: "recorded:cloudtrail-s3-data-window", Start: now.Add(-30 * 24 * time.Hour), End: now, Scopes: []ActivityScope{{PrincipalARN: arn, Action: "s3:GetObject", Resource: resource, Complete: true}, {PrincipalARN: arn, Action: "s3:PutObject", Resource: resource, Complete: true}}, Events: []Activity{{PrincipalARN: arn, Action: "s3:GetObject", Resource: resource, At: now.Add(-time.Hour)}}}}
	assessment, err := Assess(identity, input, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(assessment.Evaluations) != 3 || assessment.Evaluations[0].Unused || assessment.Evaluations[0].ObservedUses != 1 || !assessment.Evaluations[1].Unused || assessment.Evaluations[1].Result.Decision != awspolicy.Allowed {
		t.Fatalf("unused activity evidence wrong: %+v", assessment.Evaluations)
	}
	if len(assessment.Keys) != 1 || !assessment.Keys[0].LongLived || !assessment.Keys[0].Stale || len(assessment.Escalation) != 1 || assessment.Escalation[0].Confidence != "policy_candidate" {
		t.Fatalf("key/escalation findings missing: %+v", assessment)
	}
	input.Activity.Scopes = nil
	unknown, err := Assess(identity, input, now)
	if err != nil {
		t.Fatal(err)
	}
	if unknown.Evaluations[1].Unused || unknown.Evaluations[1].ActivityCoverage != awspolicy.Unavailable {
		t.Fatal("partial activity became unused proof")
	}
	input.Activity.Scopes = []ActivityScope{{PrincipalARN: arn, Action: "s3:PutObject", Resource: resource, Complete: true}}
	input.Activity.Events = append(input.Activity.Events, Activity{PrincipalARN: arn, Action: "s3:PutObject", At: now.Add(-time.Hour)})
	conservative, err := Assess(identity, input, now)
	if err != nil {
		t.Fatal(err)
	}
	if conservative.Evaluations[1].Unused {
		t.Fatal("unbound resource activity was discarded to invent an unused permission")
	}
	input.Supplemental = nil
	unread, err := Assess(identity, input, now)
	if err != nil {
		t.Fatal(err)
	}
	if unread.Evaluations[1].Result.Decision != awspolicy.Indeterminate || unread.Evaluations[1].Unused {
		t.Fatal("unread organization guardrails became a grant")
	}
	raw, err := json.Marshal(assessment)
	if err != nil || len(raw) > 512<<10 {
		t.Fatal("assessment is not a bounded serializable record")
	}
}
