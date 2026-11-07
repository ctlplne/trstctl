// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strconv"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

type dependentReconcileApprovalRequest struct {
	Intent       servicedependents.RotationIntent `json:"intent"`
	IntentDigest string                           `json:"intent_digest"`
	Reason       string                           `json:"reason"`
}
type dependentReconcileApprovalView struct {
	RequestID string    `json:"approval_request_id"`
	Digest    string    `json:"approval_intent_digest"`
	Status    string    `json:"status"`
	Required  int       `json:"required_approvals"`
	Count     int       `json:"approval_count"`
	ExpiresAt time.Time `json:"expires_at"`
}

func selectDependentRotationProvider(p dynsecret.Provider, role, mode string) (dynsecret.Provider, *servicedependents.ReconcilePrincipal, error) {
	if mode == "" {
		return p, nil, nil
	}
	if mode != servicedependents.Reconcile {
		return nil, nil, errStatus(http.StatusUnprocessableEntity, "unknown directory rotation mode")
	}
	selector, ok := p.(dynsecret.StaticReconciliationProvider)
	if !ok {
		return nil, nil, errStatus(http.StatusConflict, "provider has no separately designated reconciliation authority")
	}
	selected, pins, err := selector.StaticReconciliation(role)
	if err != nil {
		return nil, nil, errWithStatus(http.StatusConflict, err)
	}
	if selected == nil || selected.Name() != p.Name() {
		return nil, nil, errors.New("api: designated provider identity differs")
	}
	return selected, &servicedependents.ReconcilePrincipal{DN: pins.DN, SID: pins.SID, GUID: pins.GUID}, nil
}
func (a *API) dependentIntentProvider(tenantID string, intent servicedependents.RotationIntent) (dynsecret.Provider, error) {
	provider, _, err := a.staticRotationProvider(tenantID, intent.Plan.Account.ProviderID, intent.Plan.SecretName)
	if err != nil {
		return nil, err
	}
	provider, pins, err := selectDependentRotationProvider(provider, intent.Plan.SecretName, intent.Mode)
	if err != nil {
		return nil, err
	}
	if (pins == nil) != (intent.Reconcile == nil) || pins != nil && *pins != *intent.Reconcile {
		return nil, errStatus(http.StatusConflict, "designated native principal changed after review")
	}
	prepared, ok := provider.(dynsecret.PreparedStaticRotationProvider)
	if !ok || prepared.StaticRotationBinding(intent.Plan.SecretName) != intent.ProviderBinding || staticRotationPhase(provider, intent.Plan.SecretName) != dynsecret.RotationSinglePhase {
		return nil, errStatus(http.StatusConflict, "native AD provider changed after review")
	}
	return provider, nil
}
func (a *API) staticRotationCommandProvider(ctx context.Context, cmd store.SecretStaticRotationCommand) (dynsecret.Provider, dynsecret.StaticRotationProvider, error) {
	if err := a.validateDependentCommandSource(ctx, cmd); err != nil {
		return nil, nil, err
	}
	if cmd.DependentChangeID == "" {
		return a.staticRotationProvider(cmd.TenantID, cmd.Provider, cmd.Key)
	}
	parent, err := a.dependentRotationParent(ctx, cmd)
	if err != nil {
		return nil, nil, err
	}
	provider, err := a.dependentIntentProvider(cmd.TenantID, parent.Intent)
	if err != nil {
		return nil, nil, err
	}
	verifier, ok := provider.(dynsecret.StaticRotationProvider)
	if !ok {
		return nil, nil, errors.New("api: designated native verifier unavailable")
	}
	return provider, verifier, nil
}

//trstctl:mutation
func (a *API) requestPAMServiceReconciliationApproval(w http.ResponseWriter, r *http.Request) {
	a.mutateDurable(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.secrets == nil || a.orch == nil {
			return 0, nil, ErrPAMUnavailable
		}
		var req dependentReconcileApprovalRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := a.dependentRotationPermission(ctx, r, tenantID, req.Intent.Plan.SecretName); err != nil {
			return 0, nil, err
		}
		digest, err := req.Intent.Digest()
		if err != nil || digest != req.IntentDigest || req.Intent.Mode != servicedependents.Reconcile || req.Intent.Plan.Account.AccountID != r.PathValue("account_id") || strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 4096 {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "exact reconcile review and a bounded reason required")
		}
		now := time.Now().UTC()
		if !now.Before(req.Intent.Plan.ExpiresAt) || req.Intent.Plan.CreatedAt.After(now.Add(time.Minute)) {
			return 0, nil, errStatus(http.StatusConflict, "review expired; rescan before requesting reconciliation")
		}
		inputs, err := a.dependentRotationInputs(ctx, tenantID, r.PathValue("account_id"))
		if err != nil {
			return 0, nil, err
		}
		if err = req.Intent.Validate(inputs); err != nil {
			return 0, nil, errWithStatus(http.StatusConflict, err)
		}
		if _, err = a.dependentIntentProvider(tenantID, req.Intent); err != nil {
			return 0, nil, err
		}
		current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, req.Intent.Plan.SecretName)
		if err != nil {
			return 0, nil, err
		}
		if current.Version != req.Intent.ExpectedVersion {
			return 0, nil, errStatus(http.StatusConflict, staticRotationVersionMovedDetail)
		}
		actor, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		var approval store.OperationApprovalRequest
		err = a.store.WithPAMCatalogLock(ctx, tenantID, func() error {
			if _, found, err := a.log.EventByID(ctx, req.Intent.Plan.ID); err != nil {
				return err
			} else if found {
				return errStatus(http.StatusConflict, "first reconciliation command already frozen; resume its exact approval")
			}
			if _, err := a.store.GetApprovedTargetFence(ctx, tenantID, store.ApprovedTargetServiceReconciliation, servicedependents.ReconcileCommandKey(tenantID, req.Intent.Plan.SecretName)); err == nil {
				return errStatus(http.StatusConflict, "vault key has a claimed reconciliation command; resume its exact approval")
			} else if !store.IsNotFound(err) {
				return err
			}
			if err := a.retainServiceReconciliationReview(ctx, tenantID, actor, req.Intent); err != nil {
				return err
			}
			version := req.Intent.ExpectedVersion
			if version < 1 {
				return errStatus(http.StatusUnprocessableEntity, "positive retained vault version required")
			}
			var ensureErr error
			approval, ensureErr = a.orch.EnsureOperationApprovalRequest(ctx, tenantID, orchestrator.OperationApprovalIntent{ResourceKind: projections.ServiceReconcileApprovalKind, ResourceID: req.Intent.Plan.ID, ResourceName: req.Intent.Plan.Account.Name, Action: "reconcile", Requester: actor, FromState: "version:" + strconv.Itoa(req.Intent.ExpectedVersion), ToState: digest, TargetVersion: uint64(version), Reason: strings.TrimSpace(req.Reason), EvidenceRefs: []string{"service-dependent-intent:" + digest}, RequiredApprovals: 1, TTL: servicedependents.RotationInventoryMaxAge, ExpiresAtNotAfter: req.Intent.Plan.ExpiresAt})
			return ensureErr
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, dependentReconcileApprovalView{approval.ID, approval.IntentDigest, approval.Status, approval.RequiredApprovals, approval.ApprovalCount, approval.ExpiresAt}, nil
	})
}
func (a *API) dependentReconcileApprovalUse(ctx context.Context, tenantID string, req dependentRotationRequest, actor string) (*store.OperationApprovalUse, error) {
	if req.Intent.Mode == "" {
		if req.ApprovalRequestID != "" || req.ApprovalIntentDigest != "" {
			return nil, errStatus(http.StatusUnprocessableEntity, "ordinary rotation cannot consume reconcile approval")
		}
		return nil, nil
	}
	if req.ApprovalRequestID == "" || req.ApprovalIntentDigest == "" {
		return nil, errStatus(http.StatusConflict, "independent reconciliation approval required")
	}
	approval, err := a.store.GetOperationApproval(ctx, tenantID, req.ApprovalRequestID)
	if err != nil {
		return nil, approvalAPIError(err)
	}
	if approval.IntentDigest != req.ApprovalIntentDigest || approval.Requester != actor {
		return nil, errStatus(http.StatusConflict, "reconciliation approval differs from requester and reviewed effect")
	}
	use, err := store.OperationApprovalUseFromRequest(approval)
	if err != nil {
		return nil, err
	}
	if err = projections.ValidateServiceDependentRotationApproval(projections.ServiceDependentRotationQueued{Intent: req.Intent, Actor: actor, Approval: &use}); err != nil {
		return nil, errWithStatus(http.StatusConflict, err)
	}
	return &use, nil
}
func (a *API) appendDependentRotationQueued(ctx context.Context, tenantID string, queued projections.ServiceDependentRotationQueued) error {
	if err := projections.ValidateServiceDependentRotationApproval(queued); err != nil {
		return err
	}
	raw, err := json.Marshal(queued)
	if err != nil {
		return err
	}
	next := events.Event{ID: queued.Intent.Plan.ID, TenantID: tenantID, Type: projections.EventServiceDependentRotationQueued, SchemaVersion: 1, Time: queued.At, Data: raw}
	if queued.Intent.Mode == servicedependents.Reconcile {
		next.SchemaVersion = projections.ServiceDependentReconcileSchemaVersion
	}
	if err := projections.ValidateServiceDependentRotationSource(next, queued); err != nil {
		return err
	}
	if actor, ok := events.ActorFromContext(ctx); ok {
		next.Actor = &actor
	}
	if queued.Approval != nil {
		if err := a.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return a.store.ValidateServiceDependentRotationSourcesTx(ctx, tx, tenantID, queued.Intent, true)
		}); err != nil {
			return err
		}
		semantic, err := projections.ServiceReconcileSemanticDigest(next, queued)
		if err != nil {
			return err
		}
		fence, _, err := a.store.ClaimApprovedTargetFence(ctx, store.ApprovedTargetFence{TenantID: tenantID, TargetKind: store.ApprovedTargetServiceReconciliation, CommandKey: servicedependents.ReconcileCommandKey(tenantID, queued.Intent.Plan.SecretName), RequestBinding: queued.Child.RequestBinding, EventID: next.ID, EventType: next.Type, SchemaVersion: next.SchemaVersion, EventTime: next.Time, Actor: next.Actor, Payload: raw, SemanticDigest: semantic}, *queued.Approval)
		if err != nil {
			return approvalAPIError(err)
		}
		return a.projectServiceReconcileFence(ctx, tenantID, fence)
	}
	return a.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := a.store.ValidateServiceDependentRotationSourcesTx(ctx, tx, tenantID, queued.Intent, true); err != nil {
			return err
		}
		if queued.Approval != nil {
			if _, err := a.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, *queued.Approval, next.Time); err != nil {
				return approvalAPIError(err)
			}
		}
		canonical, err := a.log.Append(ctx, next)
		if err != nil {
			return err
		}
		if canonical.ID != next.ID || canonical.TenantID != tenantID || canonical.Type != next.Type || !bytes.Equal(canonical.Data, next.Data) {
			return store.ErrIdempotencyConflict
		}
		return projections.New(a.store).ApplyTx(ctx, tx, canonical)
	})
}
