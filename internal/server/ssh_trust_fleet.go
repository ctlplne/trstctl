// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

type sshTrustFleetService struct {
	store    *store.Store
	log      *events.Log
	orch     *orchestrator.Orchestrator
	required int
	enabled  bool
}

func (s *sshTrustFleetService) PreviewSSHTrustFleet(ctx context.Context, tenantID string, input api.SSHTrustFleetPreviewInput) (api.SSHTrustFleetPreview, error) {
	var out api.SSHTrustFleetPreview
	if len(input.AgentIDs) == 0 || len(input.AgentIDs) > sshtrustrollout.MaxHosts {
		return out, fmt.Errorf("%w: select between one and 100 enrolled hosts", api.ErrSSHWorkflowInvalid)
	}
	public, fingerprint, err := sshtrustrollout.CanonicalPublicCAKey([]byte(input.PublicCAKey))
	if err != nil {
		return out, fmt.Errorf("%w: %v", api.ErrSSHWorkflowInvalid, err)
	}
	plan := sshtrustrollout.Plan{Name: strings.TrimSpace(input.Name), Reason: strings.TrimSpace(input.Reason), PublicCAKey: public, CAFingerprint: fingerprint, ExpiresAt: time.Now().UTC().Add(15 * time.Minute), Hosts: []sshtrustrollout.Host{}}
	seen := map[string]bool{}
	for _, id := range input.AgentIDs {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id || seen[id] {
			return out, fmt.Errorf("%w: choose distinct canonical enrolled host IDs", api.ErrSSHWorkflowInvalid)
		}
		seen[id] = true
	}
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		for _, id := range input.AgentIDs {
			host, err := s.store.SSHTrustFleetHostTx(ctx, tx, tenantID, id, plan.CAFingerprint, now)
			if err != nil {
				return err
			}
			plan.Hosts = append(plan.Hosts, host)
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	sshtrustrollout.SortHosts(plan.Hosts)
	if err := plan.ValidateReview(); err != nil {
		return out, fmt.Errorf("%w: %v", api.ErrSSHWorkflowInvalid, err)
	}
	digest, err := plan.Digest()
	if err != nil {
		return out, fmt.Errorf("%w: %v", api.ErrSSHWorkflowInvalid, err)
	}
	out.SSHTrustFleetPlanInput = api.SSHTrustFleetPlanInput{Plan: plan, PlanDigest: digest}
	out.EffectFree = true
	out.JobKindEnabled = s.enabled
	for _, host := range plan.Hosts {
		if host.State == "ready" {
			out.ReadyHosts++
		} else {
			out.SkippedHosts++
		}
	}
	return out, nil
}

func validateSSHTrustFleetPlan(input api.SSHTrustFleetPlanInput) error {
	if err := input.Plan.ValidateReview(); err != nil {
		return fmt.Errorf("%w: %v", api.ErrSSHWorkflowInvalid, err)
	}
	digest, err := input.Plan.Digest()
	if err != nil {
		return fmt.Errorf("%w: %v", api.ErrSSHWorkflowInvalid, err)
	}
	if digest != input.PlanDigest || input.Plan.Reason != strings.TrimSpace(input.Plan.Reason) {
		return fmt.Errorf("%w: the reviewed plan digest or reason differs", api.ErrSSHWorkflowInvalid)
	}
	ready := false
	for _, host := range input.Plan.Hosts {
		if host.State == "ready" {
			ready = true
		}
	}
	if !ready {
		return fmt.Errorf("%w: no selected host has opted in and confirmed this staged CA", api.ErrSSHWorkflowInvalid)
	}
	return nil
}

func (s *sshTrustFleetService) RequestSSHTrustFleetApproval(ctx context.Context, tenantID, requester string, input api.SSHTrustFleetPlanInput) (api.SSHTrustFleetApproval, error) {
	var out api.SSHTrustFleetApproval
	if !s.enabled {
		return out, fmt.Errorf("%w: enable ssh.trust.apply in the operator-owned agent job-kind allowlist", api.ErrSSHWorkflowUnavailable)
	}
	if err := validateSSHTrustFleetPlan(input); err != nil {
		return out, err
	}
	if err := input.Plan.ExecutionWindow(time.Now().UTC()); err != nil {
		return out, fmt.Errorf("%w: %v", api.ErrSSHWorkflowInvalid, err)
	}
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return s.store.ValidateSSHTrustFleetReadyTx(ctx, tx, tenantID, input.Plan, time.Now().UTC())
	}); err != nil {
		return out, err
	}
	required := s.required
	if required <= 0 {
		required = defaultRequiredApprovals
	}
	request, err := s.orch.EnsureOperationApprovalRequest(ctx, tenantID, orchestrator.OperationApprovalIntent{ResourceKind: "ssh_trust_rollout", ResourceID: sshtrustrollout.ResourceID(input.PlanDigest), ResourceName: input.Plan.Name, Action: "apply", Requester: requester, FromState: "planned", ToState: "queued", TargetVersion: 1, Reason: input.Plan.Reason, EvidenceRefs: []string{input.PlanDigest}, RequiredApprovals: required, TTL: time.Until(input.Plan.ExpiresAt)})
	if err != nil {
		return out, err
	}
	return api.SSHTrustFleetApproval{SSHTrustFleetPlanInput: input, ApprovalRequestID: request.ID, ApprovalIntentDigest: request.IntentDigest, Status: request.Status, RequiredApprovals: request.RequiredApprovals, ApprovalCount: request.ApprovalCount, ExpiresAt: request.ExpiresAt}, nil
}

func (s *sshTrustFleetService) StartSSHTrustFleet(ctx context.Context, tenantID, requester string, input api.SSHTrustFleetStartInput) (store.SSHTrustFleetRollout, error) {
	var out store.SSHTrustFleetRollout
	if !s.enabled {
		return out, fmt.Errorf("%w: enable ssh.trust.apply in the operator-owned agent job-kind allowlist", api.ErrSSHWorkflowUnavailable)
	}
	if err := validateSSHTrustFleetPlan(input.SSHTrustFleetPlanInput); err != nil {
		return out, err
	}
	id, err := uuid.Parse(input.ApprovalRequestID)
	if err != nil || id == uuid.Nil {
		return out, store.ErrApprovalRequestNotFound
	}
	request, err := s.store.GetOperationApproval(ctx, tenantID, id.String())
	if err != nil {
		return out, err
	}
	if request.IntentDigest != input.ApprovalIntentDigest || request.Requester != requester || request.ResourceKind != "ssh_trust_rollout" || request.ResourceID != sshtrustrollout.ResourceID(input.PlanDigest) || request.ResourceName != input.Plan.Name || request.Reason != input.Plan.Reason || request.Action != "apply" {
		return out, store.ErrApprovalDigestMismatch
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		return out, err
	}
	started := projections.SSHTrustFleetStarted{ID: orchestrator.SSHTrustFleetRolloutID(tenantID, use.RequestID), Plan: input.Plan, PlanDigest: input.PlanDigest, Approval: use}
	if err := s.orch.StartSSHTrustFleet(ctx, tenantID, started); err != nil {
		return out, err
	}
	return s.GetSSHTrustFleetRollout(ctx, tenantID, started.ID)
}

func (s *sshTrustFleetService) GetSSHTrustFleetRollout(ctx context.Context, tenantID, id string) (store.SSHTrustFleetRollout, error) {
	row, err := s.store.GetSSHTrustFleetRollout(ctx, tenantID, id)
	if err != nil {
		return row, err
	}
	if err := s.bindSSHTrustFleetView(ctx, tenantID, &row); err != nil {
		return store.SSHTrustFleetRollout{}, err
	}
	return row, nil
}
func (s *sshTrustFleetService) ListSSHTrustFleetRollouts(ctx context.Context, tenantID string, after *time.Time, afterID string, limit int) ([]store.SSHTrustFleetRollout, error) {
	rows := []store.SSHTrustFleetRollout{}
	ids, err := s.store.ListSSHTrustFleetRolloutIDs(ctx, tenantID, after, afterID, limit)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		row, err := s.GetSSHTrustFleetRollout(ctx, tenantID, id)
		if errors.Is(err, store.ErrSSHTrustFleetNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func sshTrustFleetSurface(d Deps, orch *orchestrator.Orchestrator) api.SSHTrustFleetService {
	if !d.EnableAgentChannel || d.Store == nil || orch == nil {
		return nil
	}
	return &sshTrustFleetService{store: d.Store, log: d.Log, orch: orch, required: d.RequiredApprovals, enabled: AgentClaimableJobKinds(d.AgentClaimableJobKinds)[sshtrustrollout.Destination]}
}
