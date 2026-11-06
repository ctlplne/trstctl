// SPDX-License-Identifier: BUSL-1.1
package graph

import (
	"testing"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/store"
)

func cloudGraphFixture(t *testing.T) (change.Record, assessment.Assessment, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	principal := awspolicy.Principal{ARN: "arn:aws:iam::111122223333:user/orders", AccountID: "111122223333", Kind: awspolicy.IAMUser}
	value := assessment.Assessment{SourceOrigin: "https://iam.amazonaws.com", Identity: awsiam.Identity{NativeID: "AIDAOWNED", Principal: principal}}
	record := change.Record{ID: "owned-change", TenantID: "owned-tenant", State: change.Verified, ApprovalRequestID: "owned-approval", RequestedBy: "owned-requester", Intent: change.Intent{RequiredApprovals: 1, Action: change.RevokeKey, PrincipalARN: principal.ARN, PrincipalID: value.Identity.NativeID, Endpoint: value.SourceOrigin, AccessKeyID: "owned-key"}, Result: &change.Result{KeyAbsent: true, CheckedAt: now}}
	record.IntentDigest = "sha256:owned-envelope"
	return record, value, now
}
func TestGraphNativeChangeRequiresExactVerifiedEvidenceA264(t *testing.T) {
	good, value, now := cloudGraphFixture(t)
	for name, mutate := range map[string]func(*change.Record){
		"pending": func(r *change.Record) { r.State = change.Queued }, "failed": func(r *change.Record) { r.State = change.Failed },
		"uncertain": func(r *change.Record) { r.Result.EffectUncertain = true }, "error": func(r *change.Record) { r.Result.Error = "not verified" },
		"present": func(r *change.Record) { r.Result.KeyAbsent = false }, "digest": func(r *change.Record) { r.IntentDigest = "other" },
		"tenant":             func(r *change.Record) { r.TenantID = "other" },
		"different key body": func(r *change.Record) { r.Intent.AccessKeyID = "another-key" }, "native ID": func(r *change.Record) { r.Intent.PrincipalID = "" },
		"future": func(r *change.Record) { r.Result.CheckedAt = now.Add(5 * time.Minute) },
		"replacement without adoption": func(r *change.Record) {
			r.Intent.Action = change.ReplaceKey
			r.IntentDigest, _ = change.Digest(r.Intent)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := good
			result := *good.Result
			r.Result = &result
			mutate(&r)
			if _, ok := verifiedCloudGraphChange(good.TenantID, r, cloudGraphApproval(good), now); ok {
				t.Fatal("unverified change changed graph")
			}
		})
	}
	for name, mutate := range map[string]func(*store.OperationApprovalRequest){
		"unconsumed":          func(a *store.OperationApprovalRequest) { a.Status = store.ApprovalStatusApproved },
		"foreign tenant":      func(a *store.OperationApprovalRequest) { a.TenantID = "another" },
		"different body hash": func(a *store.OperationApprovalRequest) { a.ToState = "another" },
		"different envelope":  func(a *store.OperationApprovalRequest) { a.IntentDigest = "another" },
		"different resource":  func(a *store.OperationApprovalRequest) { a.ResourceID = "another" },
		"no quorum":           func(a *store.OperationApprovalRequest) { a.ApprovalCount = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			approval := cloudGraphApproval(good)
			mutate(&approval)
			if _, ok := verifiedCloudGraphChange(good.TenantID, good, approval, now); ok {
				t.Fatal("unbound approval changed graph")
			}
		})
	}

	evidence, ok := verifiedCloudGraphChange(good.TenantID, good, cloudGraphApproval(good), now)
	if !ok {
		t.Fatal("native receipt refused")
	}
	if cloudGraphAbsentKey([]cloudGraphChange{evidence}, value, now.Add(-time.Second), "owned-key") == nil {
		t.Fatal("exact older native capture not superseded")
	}
	for name, mutate := range map[string]func(*assessment.Assessment){"origin": func(v *assessment.Assessment) { v.SourceOrigin = "https://another.example" }, "immutable native ID": func(v *assessment.Assessment) { v.Identity.NativeID = "AIDARECREATED" }, "ARN": func(v *assessment.Assessment) { v.Identity.Principal.ARN += "-other" }} {
		t.Run(name, func(t *testing.T) {
			v := value
			mutate(&v)
			if cloudGraphAbsentKey([]cloudGraphChange{evidence}, v, now.Add(-time.Second), "owned-key") != nil {
				t.Fatal("another native principal was suppressed")
			}
		})
	}
	if cloudGraphAbsentKey([]cloudGraphChange{evidence}, value, now.Add(time.Second), "owned-key") != nil || cloudGraphAbsentKey([]cloudGraphChange{evidence}, value, now, "another-key") != nil {
		t.Fatal("newer observation or another key was suppressed")
	}
}
func TestGraphRestrictiveReadbackSuppressesOnlyMatchingDenyA264(t *testing.T) {
	record, value, now := cloudGraphFixture(t)
	check := assessment.Check{PrincipalARN: value.Identity.Principal.ARN, Action: "s3:GetObject", Resource: "arn:aws:s3:::owned/note", ResourceAccountID: "111122223333"}
	raw, digest, err := change.RestrictivePolicy(assessment.Assessment{Evaluations: []assessment.Evaluation{{Check: check, Unused: true, ActivityCoverage: awspolicy.Complete, Result: awspolicy.Result{Decision: awspolicy.Allowed}}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	record.Intent.Action = change.TightenPolicy
	record.Intent.PolicyDocument = raw
	record.Intent.PolicySHA256 = digest
	record.IntentDigest, _ = change.Digest(record.Intent)
	record.Result = &change.Result{PolicyMatches: true, CheckedAt: now}
	evidence, ok := verifiedCloudGraphChange(record.TenantID, record, cloudGraphApproval(record), now)
	if !ok {
		t.Fatal("native restrictive policy receipt refused")
	}
	if cloudGraphDeniedCheck([]cloudGraphChange{evidence}, value, now, check) == nil {
		t.Fatal("read-back deny left modeled access active")
	}
	other := check
	other.Action = "s3:PutObject"
	if cloudGraphDeniedCheck([]cloudGraphChange{evidence}, value, now, other) != nil {
		t.Fatal("unrelated action suppressed")
	}
	other = check
	other.Resource += "-other"
	if cloudGraphDeniedCheck([]cloudGraphChange{evidence}, value, now, other) != nil {
		t.Fatal("unrelated resource suppressed")
	}
	record.Intent.PolicySHA256 = "another"
	record.IntentDigest, _ = change.Digest(record.Intent)
	if _, ok := verifiedCloudGraphChange(record.TenantID, record, cloudGraphApproval(record), now); ok {
		t.Fatal("different policy bytes admitted")
	}
}

func cloudGraphApproval(record change.Record) store.OperationApprovalRequest {
	digest, _ := change.Digest(record.Intent)
	at := record.Result.CheckedAt.Add(-time.Second)
	return store.OperationApprovalRequest{ID: record.ApprovalRequestID, TenantID: record.TenantID, IntentDigest: record.IntentDigest, ResourceKind: "cloud_machine", ResourceID: record.ID, Action: record.Intent.Action, Requester: record.RequestedBy, FromState: record.Intent.FindingFingerprint, ToState: digest, TargetVersion: 1, RequiredApprovals: record.Intent.RequiredApprovals, ApprovalCount: record.Intent.RequiredApprovals, Reason: record.Intent.Reason, EvidenceRefs: []string{"cloud-intent-sha256:" + digest, "discovery-finding:" + record.Intent.FindingID}, Status: store.ApprovalStatusConsumed, ConsumedAt: &at, ConsumedEventID: "owned-queued-event"}
}
