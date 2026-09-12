// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

// executeIdentityTransition is the shared issuer authorization and execution
// boundary. Every operator path that issues a lifecycle credential must preserve
// these policy, approval, profile, version and replay checks.
func (a *API) executeIdentityTransition(ctx context.Context, tenantID string, principal authz.Principal, id string, req transitionRequest, idempotencyKey string, reviewed ...endpointBindingPreviewResponse) (int, any, error) {
	state := orchestrator.State(req.To)
	identity, targetVersion, err := a.store.IdentityApprovalTarget(ctx, tenantID, id)
	if err != nil {
		return 0, nil, err
	}
	csrPEM := strings.TrimSpace(req.SubjectCSRPEM)
	idempotencyKeyDigest, subjectCSRDigest := identityTransitionAttemptDigests(idempotencyKey, csrPEM)
	if csrPEM != "" {
		if state != orchestrator.StateIssued {
			return 0, nil, errStatus(http.StatusBadRequest, "subject_csr_pem is only meaningful on a transition to issued")
		}
		if err := validateSubjectCSRPEM(csrPEM); err != nil {
			// Persist this exact refusal through the bound recorder. No
			// transition, approval intent or signer/outbox call has run.
			// A lost reply can retry the SAME key and recover this specific
			// disposition; generic 4xx responses do not authorize a new key.
			refused := problem.New(http.StatusBadRequest, err.Error()).
				WithExtension("code", "identity_csr_rejected_before_transition").
				WithExtension("disposition", map[string]any{
					"tenant_id": tenantID, "subject": principal.Subject, "identity_id": id,
					"request_key": idempotencyKey, "subject_csr_sha256": subjectCSRDigest,
					"to": req.To, "reason": req.Reason,
				})
			return http.StatusBadRequest, refused, nil
		}
	}
	if _, ok := orchestrator.EventTypeFor(orchestrator.State(identity.Status), state); !ok {
		if orchestrator.State(identity.Status) == state {
			recovered, recoverErr := a.replayConsumedIdentityTransition(ctx, tenantID, id,
				principal.Subject, state, req.Reason, idempotencyKey, csrPEM,
				idempotencyKeyDigest, subjectCSRDigest)
			if recoverErr != nil {
				return 0, nil, approvalAPIError(recoverErr)
			}
			if recovered {
				updated, err := a.store.GetIdentity(ctx, tenantID, id)
				if err != nil {
					return 0, nil, err
				}
				return http.StatusOK, toIdentityResponse(updated), nil
			}
		}
		return 0, nil, &orchestrator.TransitionError{IdentityID: id, From: orchestrator.State(identity.Status), To: state}
	}
	if req.ExpectedVersion != nil && targetVersion != *req.ExpectedVersion {
		return 0, nil, lifecyclePreviewAPIError(orchestrator.ErrStaleLifecyclePreview)
	}
	gate := a.gate
	var profileReq orchestrator.ProfileApprovalRequirement
	if state == orchestrator.StateIssued && a.orch != nil {
		profileReq, err = a.orch.ProfileApprovalRequirement(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		// An identity-level profile wins. Otherwise resolve the configured
		// served default when it exists, so a display label cannot stand in
		// for the revision that will actually govern signing.
		if profileReq.ProfileName == "" && gate.Profile != "" {
			configured, resolveErr := a.orch.ProfileApprovalRequirementByName(ctx, tenantID, gate.Profile)
			if resolveErr != nil {
				// A configured label without a stored revision is not approval
				// evidence. Fail before EnsureOperationApprovalRequest so the
				// queue cannot advertise authority the dispatcher must reject.
				return 0, nil, resolveErr
			}
			profileReq = configured
		}
		gate = gateWithProfileApproval(gate, profileReq)
	}
	var issuanceBinding *store.OperationApprovalIssuanceBinding
	if state == orchestrator.StateIssued {
		issuanceBinding = profileReq.IssuanceBinding()
	}
	if len(reviewed) > 0 && (!reflect.DeepEqual(issuanceBinding, reviewed[0].Issuance) || gate.RequireApproval != reviewed[0].ApprovalRequired) {
		return 0, nil, errStatus(http.StatusConflict, "endpoint certificate profile or approval policy changed after review; build a fresh preview with a new request key")
	}
	evidenceRefs, err := identityTransitionApprovalEvidence(idempotencyKeyDigest, subjectCSRDigest, gate.Profile, issuanceBinding)
	if err != nil {
		return 0, nil, err
	}
	if req.reviewedIdentity != nil {
		raw, err := json.Marshal(req.reviewedIdentity)
		if err != nil {
			return 0, nil, err
		}
		evidenceRefs = append(evidenceRefs, "identity_snapshot_sha256:"+crypto.SHA256Hex(raw))
	}

	// Validate every part of the operation before creating an approval request.
	// An invalid transition/CSR/quota denial is not genuine work for a reviewer.
	if state == orchestrator.StateIssued {
		if err := usage.AllowCreate(ctx, tenantID, usage.MeterCertificatesStored); err != nil {
			if errors.Is(err, usage.ErrQuotaExhausted) {
				return 0, nil, errStatus(http.StatusTooManyRequests, err.Error())
			}
			return 0, nil, err
		}
	}

	var resourceAttrs map[string]string
	if a.gate.ABAC != nil {
		resourceAttrs, err = a.identityABACResourceAttrs(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		resourceAttrs["transition.to"] = req.To
	}
	authority, err := gate.checkWithApproval(ctx, principal, tenantID, id, state, resourceAttrs, &ApprovalIntent{
		ResourceKind: "identity", ResourceID: id, ResourceName: identity.Name,
		FromState: identity.Status, ToState: req.To, TargetVersion: targetVersion,
		Reason: req.Reason, EvidenceRefs: evidenceRefs,
	})
	if err != nil {
		var ge *gateError
		if errors.As(err, &ge) {
			denial := errStatus(ge.status, ge.detail)
			if ge.approval != nil && ge.approval.RequestID != "" {
				denial.ext = map[string]any{"code": "identity_approval_required", "identity_id": id,
					"approval_request_id": ge.approval.RequestID, "approval_status": ge.approval.Disposition}
			}
			return 0, nil, denial
		}
		return 0, nil, err
	}
	start := time.Now()
	var terr error
	if authority != nil {
		terr = a.orch.TransitionWithSubjectCSRAndApprovalAtVersion(ctx, tenantID, id, state,
			req.Reason, idempotencyKey, csrPEM, store.OperationApprovalUse{
				RequestID: authority.RequestID, IntentDigest: authority.IntentDigest,
				Requester: authority.Requester, ResourceKind: authority.ResourceKind,
				ResourceID: authority.ResourceID, Action: authority.Action,
				FromState: authority.FromState, ToState: authority.ToState,
				TargetVersion: authority.TargetVersion, RequiredApprovals: authority.RequiredApprovals,
				Reason: authority.Reason, EvidenceRefs: append([]string(nil), authority.EvidenceRefs...),
				Issuance: authority.Issuance,
			}, req.ExpectedVersion, req.reviewedIdentity)
	} else {
		terr = a.orch.TransitionWithSubjectCSRAtIdentitySnapshot(ctx, tenantID, id, state, req.Reason, idempotencyKey, csrPEM, req.ExpectedVersion, req.reviewedIdentity, issuanceBinding)
	}
	if feature, action, ok := transitionFeatureAction(state); ok {
		a.observeFeature(feature, action, start, terr)
	}
	if terr != nil {
		return 0, nil, lifecyclePreviewAPIError(approvalAPIError(terr))
	}
	updated, err := a.store.GetIdentity(ctx, tenantID, id)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, toIdentityResponse(updated), nil
}
