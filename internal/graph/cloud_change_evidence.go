// SPDX-License-Identifier: BUSL-1.1
package graph

import (
	"context"
	"errors"
	"sort"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

type cloudGraphChange struct {
	record change.Record
	deny   *awspolicy.Document
}

func loadCloudGraphChanges(ctx context.Context, st *store.Store, tenantID string, now time.Time) ([]cloudGraphChange, error) {
	var out []cloudGraphChange
	after := ""
	for {
		records, err := st.ListCloudMachineChanges(ctx, tenantID, after, 200)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			after = record.ID
			if record.State != change.Verified {
				continue
			}
			approval, err := st.GetOperationApproval(ctx, tenantID, record.ApprovalRequestID)
			if errors.Is(err, store.ErrApprovalRequestNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if evidence, ok := verifiedCloudGraphChange(tenantID, record, approval, now); ok {
				out = append(out, evidence)
			}
		}
		if len(records) < 200 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].record.Result.CheckedAt.Equal(out[j].record.Result.CheckedAt) {
			return out[i].record.ID > out[j].record.ID
		}
		return out[i].record.Result.CheckedAt.After(out[j].record.Result.CheckedAt)
	})
	return out, nil
}

// Immutable native result evidence can supersede older observations. Neither a
// pending proposal nor an ARN/name match alone changes graph reachability.
func verifiedCloudGraphChange(tenantID string, record change.Record, approval store.OperationApprovalRequest, now time.Time) (cloudGraphChange, bool) {
	if record.TenantID != tenantID || record.State != change.Verified || record.Intent.PrincipalID == "" || record.Intent.Endpoint == "" || record.Result == nil || record.Result.CheckedAt.IsZero() || record.Result.CheckedAt.After(now.Add(time.Minute)) {
		return cloudGraphChange{}, false
	}
	digest, err := change.Digest(record.Intent)
	if err != nil || approval.TenantID != tenantID || approval.ID != record.ApprovalRequestID || approval.Status != store.ApprovalStatusConsumed || approval.ConsumedAt == nil || approval.ConsumedEventID == "" || approval.ApprovalCount < approval.RequiredApprovals {
		return cloudGraphChange{}, false
	}
	// The body digest is ToState inside the approved envelope. IntentDigest is
	// the envelope digest, not a second encoding of the body hash.
	use := store.OperationApprovalUse{RequestID: record.ApprovalRequestID, IntentDigest: record.IntentDigest, Requester: record.RequestedBy, ResourceKind: "cloud_machine", ResourceID: record.ID, Action: record.Intent.Action, FromState: record.Intent.FindingFingerprint, ToState: digest, TargetVersion: 1, RequiredApprovals: record.Intent.RequiredApprovals, Reason: record.Intent.Reason, EvidenceRefs: []string{"discovery-finding:" + record.Intent.FindingID, "cloud-intent-sha256:" + digest}}
	sort.Strings(use.EvidenceRefs)
	if store.ValidateOperationApprovalUseBinding(approval, use) != nil {
		return cloudGraphChange{}, false
	}
	current := record
	current.State = change.Queued
	if record.Intent.Action == change.ReplaceKey {
		current.State = change.WaitingAdoption
	}
	if change.ValidateProgress(current, change.Verified, record.Result) != nil {
		return cloudGraphChange{}, false
	}
	out := cloudGraphChange{record: record}
	if record.Intent.Action == change.TightenPolicy {
		if crypto.SHA256Hex(record.Intent.PolicyDocument) != record.Intent.PolicySHA256 {
			return cloudGraphChange{}, false
		}
		doc, err := awspolicy.Parse(record.ID, record.Intent.PolicyDocument)
		if err != nil {
			return cloudGraphChange{}, false
		}
		out.deny = &doc
	}
	return out, true
}
func cloudGraphChangeApplies(e cloudGraphChange, value assessment.Assessment, observedAt time.Time) bool {
	i := e.record.Intent
	return i.PrincipalARN == value.Identity.Principal.ARN && i.PrincipalID == value.Identity.NativeID && i.Endpoint == value.SourceOrigin && !observedAt.After(e.record.Result.CheckedAt)
}
func cloudGraphAbsentKey(changes []cloudGraphChange, value assessment.Assessment, observedAt time.Time, keyID string) *change.Record {
	for _, e := range changes {
		if cloudGraphChangeApplies(e, value, observedAt) && e.record.Result.KeyAbsent && e.record.Intent.AccessKeyID == keyID && (e.record.Intent.Action == change.RevokeKey || e.record.Intent.Action == change.ReplaceKey) {
			record := e.record
			return &record
		}
	}
	return nil
}
func cloudGraphDeniedCheck(changes []cloudGraphChange, value assessment.Assessment, observedAt time.Time, check assessment.Check) *change.Record {
	for _, e := range changes {
		if e.deny == nil || !cloudGraphChangeApplies(e, value, observedAt) {
			continue
		}
		result := awspolicy.Evaluate(awspolicy.Request{Principal: value.Identity.Principal, Action: check.Action, Resource: check.Resource, ResourceAccountID: check.ResourceAccountID, Context: check.Context}, awspolicy.Evidence{Identity: awspolicy.PolicySet{Coverage: awspolicy.Complete, Documents: []awspolicy.Document{*e.deny}}, Resource: awspolicy.PolicySet{Coverage: awspolicy.Absent}, Boundary: awspolicy.PolicySet{Coverage: awspolicy.Absent}, Session: awspolicy.PolicySet{Coverage: awspolicy.Absent}, SCPCoverage: awspolicy.Absent, RCPCoverage: awspolicy.Absent})
		if result.Decision == awspolicy.ExplicitDeny {
			record := e.record
			return &record
		}
	}
	return nil
}
