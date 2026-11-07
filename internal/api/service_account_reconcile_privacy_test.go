// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"testing"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestConsumedReconcileReadAuthorityRequiresExactClosedPrivacyMarkerA267(t *testing.T) {
	const root = "57600000-0000-4000-8000-000000000001"
	marker := privacy.Placeholder(privacy.SubjectRef("57600000-0000-4000-8000-000000000002", "owned-requester"))
	use := store.OperationApprovalUse{RequestID: "57600000-0000-4000-8000-000000000003", IntentDigest: "sha256:owned-approved-effect", Requester: marker, ResourceKind: "pam_service_reconcile", ResourceID: root, Action: "reconcile", FromState: "version:1", ToState: "owned-intent-digest", TargetVersion: 1, RequiredApprovals: 1, EvidenceRefs: []string{"service-dependent-intent:owned-intent-digest"}}
	request := store.OperationApprovalRequest{ID: use.RequestID, IntentDigest: use.IntentDigest, Requester: marker, ResourceKind: marker, ResourceID: marker, ResourceName: marker, Action: marker, FromState: marker, ToState: marker, TargetVersion: 1, RequiredApprovals: 1, Status: store.ApprovalStatusConsumed, ConsumedEventID: root}
	if store.ValidateOperationApprovalUseBinding(request, use) == nil {
		t.Fatal("generic approval validator accepted a rewritten marker as fresh authority")
	}
	if err := validateConsumedReconcileReadAuthority(root, "owned-service", use, request); err != nil {
		t.Fatal("already-consumed canonical read could not survive exact privacy preparation", err)
	}
	for name, mutate := range map[string]func(*store.OperationApprovalRequest){
		"pending":             func(r *store.OperationApprovalRequest) { r.Status = store.ApprovalStatusPending },
		"approved":            func(r *store.OperationApprovalRequest) { r.Status = store.ApprovalStatusApproved },
		"another consumption": func(r *store.OperationApprovalRequest) { r.ConsumedEventID = "57600000-0000-4000-8000-000000000009" },
		"another request":     func(r *store.OperationApprovalRequest) { r.ID = "57600000-0000-4000-8000-000000000009" },
		"another digest":      func(r *store.OperationApprovalRequest) { r.IntentDigest = "sha256:other" },
		"target version":      func(r *store.OperationApprovalRequest) { r.TargetVersion++ },
		"quorum":              func(r *store.OperationApprovalRequest) { r.RequiredApprovals++ },
		"partial kind":        func(r *store.OperationApprovalRequest) { r.ResourceKind = "pam_service_reconcile" },
		"partial resource":    func(r *store.OperationApprovalRequest) { r.ResourceID = root },
		"partial name":        func(r *store.OperationApprovalRequest) { r.ResourceName = "owned-service" },
		"partial action":      func(r *store.OperationApprovalRequest) { r.Action = "reconcile" },
		"partial source":      func(r *store.OperationApprovalRequest) { r.FromState = "version:1" },
		"partial target":      func(r *store.OperationApprovalRequest) { r.ToState = use.ToState },
		"reason":              func(r *store.OperationApprovalRequest) { r.Reason = "uncleared" },
		"evidence":            func(r *store.OperationApprovalRequest) { r.EvidenceRefs = []string{"uncleared"} },
		"ordinary requester":  func(r *store.OperationApprovalRequest) { r.Requester = "owned-requester" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := request
			mutate(&bad)
			if validateConsumedReconcileReadAuthority(root, "owned-service", use, bad) == nil {
				t.Fatal("partial or unspent SQL marker replaced canonical consumed authority")
			}
		})
	}
	rawUse := use
	rawUse.Requester = "owned-requester"
	if validateConsumedReconcileReadAuthority(root, "owned-service", rawUse, request) == nil {
		t.Fatal("unerased canonical actor accepted an erased SQL marker")
	}
	retained := request
	retained.Requester = "retained:012345abcdef"
	retained.ResourceKind, retained.ResourceID, retained.ResourceName = rawUse.ResourceKind, rawUse.ResourceID, "owned-service"
	retained.Action, retained.FromState, retained.ToState = rawUse.Action, rawUse.FromState, rawUse.ToState
	if err := validateConsumedReconcileReadAuthority(root, "owned-service", rawUse, retained); err != nil {
		t.Fatal("closed canonical read could not survive retention", err)
	}
	retained.ToState = "changed-effect"
	if validateConsumedReconcileReadAuthority(root, "owned-service", rawUse, retained) == nil {
		t.Fatal("retention marker changed the frozen effect")
	}
}
