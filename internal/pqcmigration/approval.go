// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Approval-gated PQC migration starts (A40).
//
// A reissue whose certificate profile requires a distinct issuance approval
// used to be refused at start. The start itself is now the approved
// operation: the first attempt records an immutable approval request bound
// to the canonical selection and every gated reissue's frozen issuance
// binding, reviewers approve it with its intent digest, and the next identical
// start consumes that exact authority in the same transaction that records
// the run. A changed selection, profile revision or lifetime is a different
// request.

// pqcMigrationApprovalIntent builds the immutable intent for one start.
func pqcMigrationApprovalIntent(tenantID, principal string, req APIRequest, bindings map[string]certificateExecutionBinding) (orchestrator.OperationApprovalIntent, error) {
	if tenantID == "" || principal == "" {
		return orchestrator.OperationApprovalIntent{}, errors.New("pqcmigration: approval intent requires tenant and requester")
	}
	canonical := struct {
		AssetIDs            []string                `json:"asset_ids"`
		TargetAlgorithm     string                  `json:"target_algorithm"`
		Protocol            string                  `json:"protocol"`
		RollbackOnFailure   bool                    `json:"rollback_on_failure"`
		CertificateBindings []APICertificateBinding `json:"certificate_bindings"`
		TLSBindings         []APITLSBinding         `json:"tls_bindings"`
	}{
		AssetIDs: append([]string(nil), req.AssetIDs...), TargetAlgorithm: req.TargetAlgorithm, Protocol: req.Protocol,
		RollbackOnFailure:   req.RollbackOnFailure,
		CertificateBindings: append([]APICertificateBinding(nil), req.CertificateBindings...),
		TLSBindings:         append([]APITLSBinding(nil), req.TLSBindings...),
	}
	sort.Strings(canonical.AssetIDs)
	sort.Slice(canonical.CertificateBindings, func(i, j int) bool {
		return canonical.CertificateBindings[i].AssetID < canonical.CertificateBindings[j].AssetID
	})
	sort.Slice(canonical.TLSBindings, func(i, j int) bool { return canonical.TLSBindings[i].AssetID < canonical.TLSBindings[j].AssetID })
	raw, err := json.Marshal(canonical)
	if err != nil {
		return orchestrator.OperationApprovalIntent{}, err
	}
	digest := crypto.SHA256Hex(raw)
	refs := []string{"pqc-migration-intent:" + digest, "target-algorithm:" + req.TargetAlgorithm}
	for assetID, binding := range bindings {
		if !binding.RequiresApproval {
			continue
		}
		b := binding.Issuance
		refs = append(refs, fmt.Sprintf("asset:%s:identity:%s:profile:%s:profile-id:%s:profile-version:%d:profile-spec-digest:%s:ttl:%d/%d",
			assetID, binding.Identity.ID, b.ProfileName, b.ProfileID, b.ProfileVersion, b.ProfileSpecDigest, b.RequestedTTLSeconds, b.EffectiveTTLSeconds))
	}
	sort.Strings(refs[2:])
	return orchestrator.OperationApprovalIntent{
		ResourceKind: "pqc_migration_run", ResourceID: "pqc-migration:" + digest, ResourceName: "pqc-migration:" + digest[:16],
		Action: "start", Requester: principal,
		Reason:       "start a PQC certificate migration whose reissues run under an approval-required certificate profile",
		EvidenceRefs: refs,
	}, nil
}

// pqcMigrationApprovalReady reports whether the request can authorize a start now.
func pqcMigrationApprovalReady(request store.OperationApprovalRequest, now time.Time) bool {
	return request.Status == store.ApprovalStatusApproved && request.ApprovalCount >= request.RequiredApprovals && now.Before(request.ExpiresAt)
}

func pqcMigrationApprovalTerminal(request store.OperationApprovalRequest, now time.Time) (string, bool) {
	switch request.Status {
	case store.ApprovalStatusConsumed, store.ApprovalStatusSuperseded, store.ApprovalStatusDenied, store.ApprovalStatusExpired:
		return request.Status, true
	}
	if !now.Before(request.ExpiresAt) {
		return store.ApprovalStatusExpired, true
	}
	return "", false
}

// authorizePQCMigrationStart returns the consumed-to-be approval use for a
// gated start, a pending response when reviewers have not finished, or a
// conflict when the request can no longer authorize anything.
func (s *pqcMigrationService) authorizePQCMigrationStart(ctx context.Context, tenantID string, req APIRequest, bindings map[string]certificateExecutionBinding) (*store.OperationApprovalUse, *Response, error) {
	gated := false
	for _, binding := range bindings {
		if binding.RequiresApproval {
			gated = true
			break
		}
	}
	if !gated {
		return nil, nil, nil
	}
	principal, err := api.AuthenticatedPrincipalSubject(ctx)
	if err != nil {
		return nil, nil, err
	}
	intent, err := pqcMigrationApprovalIntent(tenantID, principal, req, bindings)
	if err != nil {
		return nil, nil, err
	}
	orch := orchestrator.NewOrchestrator(s.log, s.store, s.outbox)
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantID, intent)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	if status, terminal := pqcMigrationApprovalTerminal(request, now); terminal {
		return nil, nil, api.ErrStatus(http.StatusConflict, fmt.Sprintf(
			"PQC migration start approval request %s (%s) is %s; a changed selection creates a new request", request.ID, request.IntentDigest, status))
	}
	if !pqcMigrationApprovalReady(request, now) {
		return nil, &Response{
			Status: "pending_approval", ApprovalRequestID: request.ID, IntentDigest: request.IntentDigest,
			RequiredApprovals: request.RequiredApprovals, ApprovalCount: request.ApprovalCount,
			TargetAlgorithm: req.TargetAlgorithm, Protocol: req.Protocol,
			Detail: "a selected reissue runs under an approval-required certificate profile; approve request " + request.ID +
				" with its intent digest, then post this exact start again under a new Idempotency-Key",
		}, nil
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		return nil, nil, err
	}
	return &use, nil, nil
}
