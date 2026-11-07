// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A276: brokered accounts whose owner is gone — none assigned, the owner
// record deleted, or a person owner offboarded — or that sat unused past the
// deployment's window are flagged. An action proposed on a flag (reassign
// the owner, or rotate the account's vaulted credential and disable it)
// needs approval; applying it consumes the approval once, and the flag and
// the account read back what it did.

const (
	// pamUnusedAfterDefault is how long an account may go without a session
	// or check-out before it is flagged unused.
	pamUnusedAfterDefault = 90 * 24 * time.Hour
	// pamFlagScanInterval is how often the PAM worker scans for flags.
	pamFlagScanInterval = 15 * time.Minute
	pamFlagReasonMax    = 500
)

func unusedAfterOrDefault(d time.Duration) time.Duration {
	if d <= 0 {
		return pamUnusedAfterDefault
	}
	return d
}

func flagView(f store.PAMAccountFlag) api.PAMAccountFlag {
	return api.PAMAccountFlag{TargetType: f.TargetType, TargetID: f.TargetID, Reasons: f.Reasons, Detail: f.Detail, OwnerID: f.OwnerID,
		LastUsedAt: f.LastUsedAt, FlaggedAt: f.FlaggedAt.UTC(), Status: f.Status, ClearedAt: f.ClearedAt, Action: f.Action,
		ActionOwnerID: f.ActionOwnerID, ActionRotationID: f.ActionRotationID, ActionReason: f.ActionReason,
		ApprovalRequestID: f.ApprovalRequestID, ActionedBy: f.ActionedBy, ActionedAt: f.ActionedAt}
}

// ListPAMAccountFlags is a tenant's flags, newest first.
func (s *pamService) ListPAMAccountFlags(ctx context.Context, tenantID, status string) ([]api.PAMAccountFlag, error) {
	flags, err := s.store.ListPAMAccountFlags(ctx, tenantID, status)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMAccountFlag, 0, len(flags))
	for _, f := range flags {
		out = append(out, flagView(f))
	}
	return out, nil
}

// ScanPAMAccountFlags flags the tenant's accounts now and returns its open
// flags.
func (s *pamService) ScanPAMAccountFlags(ctx context.Context, tenantID string) ([]api.PAMAccountFlag, error) {
	if err := s.scanTenantAccountFlags(ctx, tenantID); err != nil {
		return nil, err
	}
	return s.ListPAMAccountFlags(ctx, tenantID, "open")
}

// scanAccountFlags is the PAM worker's scan of every tenant with brokered
// accounts, at most once per pamFlagScanInterval.
func (s *pamService) scanAccountFlags(ctx context.Context) {
	now := s.clock()
	if !s.lastFlagScan.IsZero() && now.Sub(s.lastFlagScan) < pamFlagScanInterval {
		return
	}
	s.lastFlagScan = now
	tenants := map[string]bool{}
	for key := range s.databases {
		tenants[key.tenantID] = true
	}
	for key := range s.sshTargets {
		tenants[key.tenantID] = true
	}
	registered, err := s.store.ListTenantsWithPAMTargets(ctx, 0)
	if err != nil {
		return
	}
	for _, t := range registered {
		tenants[t] = true
	}
	for tenantID := range tenants {
		if ctx.Err() != nil {
			return
		}
		_ = s.scanTenantAccountFlags(ctx, tenantID)
	}
}

// scanTenantAccountFlags opens a flag for each enabled account with a
// reason, refreshes one whose reasons changed, and clears one whose reasons
// no longer hold. One scan of a tenant runs at a time.
func (s *pamService) scanTenantAccountFlags(ctx context.Context, tenantID string) error {
	return s.store.WithPAMCatalogLock(ctx, tenantID, func() error { return s.scanTenantAccountFlagsLocked(ctx, tenantID) })
}

func (s *pamService) scanTenantAccountFlagsLocked(ctx context.Context, tenantID string) error {
	targets, err := s.ListPAMTargets(ctx, tenantID)
	if err != nil {
		return err
	}
	owners, err := s.store.ListOwners(ctx, tenantID)
	if err != nil {
		return err
	}
	byID := make(map[string]store.Owner, len(owners))
	for _, o := range owners {
		byID[o.ID] = o
	}
	members, err := s.store.ListTenantMembersPage(ctx, tenantID, "", true, 10000)
	if err != nil {
		return err
	}
	active, offboarded := map[string]bool{}, map[string]bool{}
	for _, m := range members {
		email := strings.ToLower(strings.TrimSpace(m.Email))
		if email == "" {
			continue
		}
		if m.OffboardedAt != nil || m.Status == "offboarded" {
			offboarded[email] = true
		} else {
			active[email] = true
		}
	}
	uses, err := s.store.PAMAccountLastUses(ctx, tenantID)
	if err != nil {
		return err
	}
	existing, err := s.store.ListPAMAccountFlags(ctx, tenantID, "")
	if err != nil {
		return err
	}
	flags := make(map[[2]string]store.PAMAccountFlag, len(existing))
	for _, f := range existing {
		flags[[2]string{f.TargetType, f.TargetID}] = f
	}
	now := s.clock().UTC()
	for _, target := range targets {
		key := [2]string{target.TargetType, target.ID}
		flag, flagged := flags[key]
		if !target.Enabled {
			if flagged && flag.Status == "open" {
				if err := s.appendProject(ctx, tenantID, projections.EventPAMAccountFlagCleared,
					projections.PAMAccountFlagCleared{TargetType: target.TargetType, TargetID: target.ID, At: now}); err != nil {
					return err
				}
			}
			continue
		}
		var reasons, detail []string
		switch owner, known := byID[target.OwnerID]; {
		case target.OwnerID == "":
			reasons, detail = append(reasons, "orphaned"), append(detail, "it has no owner")
		case !known:
			reasons, detail = append(reasons, "orphaned"), append(detail, "its owner record is gone")
		case owner.Kind == store.OwnerUser && owner.Email != "" && offboarded[strings.ToLower(owner.Email)] && !active[strings.ToLower(owner.Email)]:
			reasons, detail = append(reasons, "orphaned"), append(detail, "its owner "+owner.Name+" was offboarded")
		}
		var lastUsed *time.Time
		baseline := target.RegisteredAt
		if at, ok := uses[key]; ok {
			at = at.UTC()
			lastUsed, baseline = &at, &at
		}
		if baseline != nil && now.Sub(*baseline) > s.unusedAfter {
			reasons = append(reasons, "unused")
			if lastUsed != nil {
				detail = append(detail, "unused since "+lastUsed.Format(time.RFC3339))
			} else {
				detail = append(detail, "never used since it was registered "+baseline.UTC().Format(time.RFC3339))
			}
		}
		switch {
		case len(reasons) > 0 && (!flagged || flag.Status != "open" || !slices.Equal(flag.Reasons, reasons) || flag.OwnerID != target.OwnerID):
			if flagged && flag.Status == "actioned" && flag.Action == "reassign" && slices.Equal(reasons, []string{"unused"}) && flag.ActionedAt != nil &&
				lastUsed == nil {
				// A reassigned account that was never used stays resolved until
				// its new owner's window passes.
				if now.Sub(*flag.ActionedAt) <= s.unusedAfter {
					continue
				}
			}
			if err := s.appendProject(ctx, tenantID, projections.EventPAMAccountFlagged, projections.PAMAccountFlagged{TargetType: target.TargetType,
				TargetID: target.ID, Reasons: reasons, Detail: strings.Join(detail, "; "), OwnerID: target.OwnerID, LastUsedAt: lastUsed, At: now}); err != nil {
				return err
			}
		case len(reasons) == 0 && flagged && flag.Status == "open":
			if err := s.appendProject(ctx, tenantID, projections.EventPAMAccountFlagCleared,
				projections.PAMAccountFlagCleared{TargetType: target.TargetType, TargetID: target.ID, At: now}); err != nil {
				return err
			}
		}
	}
	return nil
}

// pamAccountIntent is a proposed action's exact approval intent, bound to
// the flag it resolves.
func (s *pamService) pamAccountIntent(ctx context.Context, tenantID, requester, targetType, id string, req api.PAMAccountActionRequest) (orchestrator.OperationApprovalIntent, store.PAMAccountFlag, error) {
	req.Reason = strings.TrimSpace(req.Reason)
	if requester == "" || !validUUID(req.RequestID) || req.Reason == "" || utf8.RuneCountInString(req.Reason) > pamFlagReasonMax || strings.ContainsAny(req.Reason, "\r\n") {
		return orchestrator.OperationApprovalIntent{}, store.PAMAccountFlag{}, fmt.Errorf("%w: a request_id and a one-line reason of 1-%d characters are required", api.ErrPAMInvalid, pamFlagReasonMax)
	}
	if req.Action != "reassign" && req.Action != "rotate_disable" {
		return orchestrator.OperationApprovalIntent{}, store.PAMAccountFlag{}, fmt.Errorf("%w: action must be reassign or rotate_disable", api.ErrPAMInvalid)
	}
	if (req.Action == "reassign") != (req.OwnerID != "") {
		return orchestrator.OperationApprovalIntent{}, store.PAMAccountFlag{}, fmt.Errorf("%w: a reassignment names its new owner, and only a reassignment does", api.ErrPAMInvalid)
	}
	flag, err := s.store.GetPAMAccountFlag(ctx, tenantID, targetType, id)
	if err != nil {
		return orchestrator.OperationApprovalIntent{}, store.PAMAccountFlag{}, err
	}
	target, err := s.getPAMTarget(ctx, tenantID, targetType, id)
	if err != nil {
		return orchestrator.OperationApprovalIntent{}, store.PAMAccountFlag{}, err
	}
	toState := "reassigned"
	evidence := []string{"pam-account-flag:" + strings.Join(flag.Reasons, ","), "pam-account-flagged-at:" + flag.FlaggedAt.UTC().Format(time.RFC3339Nano),
		"pam-account-request:" + req.RequestID}
	if req.Action == "reassign" {
		if _, err := s.store.GetOwner(ctx, tenantID, req.OwnerID); err != nil {
			return orchestrator.OperationApprovalIntent{}, store.PAMAccountFlag{}, fmt.Errorf("%w: owner %s is not one of the tenant's owners", api.ErrPAMInvalid, req.OwnerID)
		}
		evidence = append(evidence, "pam-account-new-owner:"+req.OwnerID)
	} else {
		if target.Source != "tenant" {
			return orchestrator.OperationApprovalIntent{}, store.PAMAccountFlag{}, fmt.Errorf("%w: an operator-configured account is disabled by removing it from the deployment's configuration", api.ErrPAMTargetConflict)
		}
		toState = "disabled"
		if target.AccountSecret != "" {
			evidence = append(evidence, "pam-account-rotate:"+target.ProviderID+"/"+target.AccountSecret)
			pair, twoUser := s.twoUserAccounts(tenantID, target.ProviderID, target.AccountSecret)
			switch {
			case twoUser && req.RotationOldRef != pair[0] && req.RotationOldRef != pair[1]:
				return orchestrator.OperationApprovalIntent{}, store.PAMAccountFlag{}, fmt.Errorf("%w: rotation_old_ref must name the account its consumers use now: %s or %s", api.ErrPAMInvalid, pair[0], pair[1])
			case twoUser:
				evidence = append(evidence, "pam-account-rotate-from:"+req.RotationOldRef)
			case req.RotationOldRef != "":
				return orchestrator.OperationApprovalIntent{}, store.PAMAccountFlag{}, fmt.Errorf("%w: rotation_old_ref is only for an account its provider rotates between two", api.ErrPAMInvalid)
			}
		}
	}
	return orchestrator.OperationApprovalIntent{ResourceKind: "pam_account", ResourceID: "pam-account:" + targetType + "/" + id, ResourceName: id,
		Action: req.Action, Requester: requester, FromState: "flagged", ToState: toState, Reason: req.Reason, EvidenceRefs: evidence,
		RequiredApprovals: s.requiredApprovals, TTL: s.approvalTTL}, flag, nil
}

// RequestPAMAccountAction proposes an action on an open flag for approval.
func (s *pamService) RequestPAMAccountAction(ctx context.Context, tenantID, requester, targetType, id string, req api.PAMAccountActionRequest) (api.PAMAccountActionReview, error) {
	intent, flag, err := s.pamAccountIntent(ctx, tenantID, requester, targetType, id, req)
	if err != nil {
		return api.PAMAccountActionReview{}, err
	}
	if flag.Status != "open" {
		return api.PAMAccountActionReview{}, fmt.Errorf("%w: the account's flag is %s; only an open flag takes an action", api.ErrPAMTargetConflict, flag.Status)
	}
	approval, err := s.orch.EnsureOperationApprovalRequest(ctx, tenantID, intent)
	if err != nil {
		return api.PAMAccountActionReview{}, err
	}
	return api.PAMAccountActionReview{RequestID: req.RequestID, ApprovalRequestID: approval.ID, IntentDigest: approval.IntentDigest,
		Status: approval.Status, ApprovalCount: approval.ApprovalCount, RequiredApprovals: approval.RequiredApprovals, ExpiresAt: approval.ExpiresAt}, nil
}

// approvedPAMAccountAction is the approval an apply consumes: it must be the
// one this requester asked for, for this account, action and flag.
func (s *pamService) approvedPAMAccountAction(ctx context.Context, tenantID, requester, targetType, id string, req api.PAMAccountActionRequest) (store.OperationApprovalRequest, store.PAMAccountFlag, error) {
	if !validUUID(req.ApprovalRequestID) || req.IntentDigest == "" {
		return store.OperationApprovalRequest{}, store.PAMAccountFlag{}, fmt.Errorf("%w: the approval's exact approval_request_id and intent_digest are required", api.ErrPAMInvalid)
	}
	intent, flag, err := s.pamAccountIntent(ctx, tenantID, requester, targetType, id, req)
	if err != nil {
		return store.OperationApprovalRequest{}, store.PAMAccountFlag{}, err
	}
	approval, err := s.store.GetOperationApproval(ctx, tenantID, req.ApprovalRequestID)
	if err != nil {
		return store.OperationApprovalRequest{}, store.PAMAccountFlag{}, err
	}
	if approval.ResourceKind != intent.ResourceKind || approval.ResourceID != intent.ResourceID || approval.Action != intent.Action ||
		approval.Requester != requester || approval.IntentDigest != req.IntentDigest || !sameEvidence(approval.EvidenceRefs, intent.EvidenceRefs) {
		return store.OperationApprovalRequest{}, store.PAMAccountFlag{}, fmt.Errorf("%w: the approval does not belong to this requester, account, action and flag; request a new review", api.ErrPAMRejected)
	}
	return approval, flag, nil
}

// sameEvidence compares two evidence lists as sets; an approval request keeps
// its evidence in canonical order.
func sameEvidence(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// PlanPAMAccountAction checks an apply's approval and says what applying it
// rotates first.
func (s *pamService) PlanPAMAccountAction(ctx context.Context, tenantID, requester, targetType, id string, req api.PAMAccountActionRequest) (api.PAMAccountActionPlan, error) {
	if _, _, err := s.approvedPAMAccountAction(ctx, tenantID, requester, targetType, id, req); err != nil {
		return api.PAMAccountActionPlan{}, err
	}
	if req.Action != "rotate_disable" {
		return api.PAMAccountActionPlan{}, nil
	}
	target, err := s.getPAMTarget(ctx, tenantID, targetType, id)
	if err != nil {
		return api.PAMAccountActionPlan{}, err
	}
	oldRef := "none"
	if _, twoUser := s.twoUserAccounts(tenantID, target.ProviderID, target.AccountSecret); twoUser {
		oldRef = req.RotationOldRef
	}
	return api.PAMAccountActionPlan{RotateProvider: target.ProviderID, RotateKey: target.AccountSecret, RotateOldRef: oldRef}, nil
}

// twoUserAccounts is the pair a provider rotates a role's account between,
// when it does (A240).
func (s *pamService) twoUserAccounts(tenantID, providerID, role string) ([2]string, bool) {
	for _, provider := range s.providers.ForTenant(tenantID) {
		if provider == nil || provider.Name() != providerID {
			continue
		}
		if twoUser, ok := provider.(dynsecret.TwoUserRotationProvider); ok {
			return twoUser.RotationAccounts(role)
		}
	}
	return [2]string{}, false
}

// ApplyPAMAccountAction applies an approved action once: the new owner's
// assignment, or the target disabled (its rotation already queued), then
// the flag's actioned event consuming the approval.
func (s *pamService) ApplyPAMAccountAction(ctx context.Context, tenantID, requester, targetType, id string, req api.PAMAccountActionRequest, rotationID string) (api.PAMAccountFlag, error) {
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-account-flag\x00"+tenantID+"\x00"+req.ApprovalRequestID)).String()
	canonical, found, err := s.log.EventByID(ctx, eventID)
	if err != nil {
		return api.PAMAccountFlag{}, err
	}
	if found {
		var done projections.PAMAccountFlagActioned
		if canonical.Type != projections.EventPAMAccountFlagActioned || canonical.TenantID != tenantID || json.Unmarshal(canonical.Data, &done) != nil ||
			done.TargetType != targetType || done.TargetID != id || done.Actor != requester {
			return api.PAMAccountFlag{}, fmt.Errorf("%w: the approval was applied to a different action", orchestrator.ErrIdempotencyConflict)
		}
		flag, err := s.store.GetPAMAccountFlag(ctx, tenantID, targetType, id)
		return flagView(flag), err
	}
	approval, flag, err := s.approvedPAMAccountAction(ctx, tenantID, requester, targetType, id, req)
	if err != nil {
		return api.PAMAccountFlag{}, err
	}
	if flag.Status != "open" {
		return api.PAMAccountFlag{}, fmt.Errorf("%w: the account's flag is %s; only an open flag takes an action", api.ErrPAMTargetConflict, flag.Status)
	}
	use, err := store.OperationApprovalUseFromRequest(approval)
	if err != nil {
		return api.PAMAccountFlag{}, err
	}
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, use, s.clock().UTC())
		return err
	}); err != nil {
		return api.PAMAccountFlag{}, err
	}
	reason := strings.TrimSpace(req.Reason)
	switch req.Action {
	case "reassign":
		if _, err := s.orch.AssignOwnership(ctx, tenantID, req.OwnerID, []string{api.PAMAccountInventoryID(targetType, id)},
			"A276 approved reassignment ("+approval.ID+"): "+reason, requester); err != nil {
			return api.PAMAccountFlag{}, err
		}
	case "rotate_disable":
		target, err := s.getPAMTarget(ctx, tenantID, targetType, id)
		if err != nil {
			return api.PAMAccountFlag{}, err
		}
		if target.AccountSecret != "" && rotationID == "" {
			return api.PAMAccountFlag{}, fmt.Errorf("%w: the account's credential rotation was not queued", api.ErrPAMRejected)
		}
		if target.Enabled {
			if _, err := s.DisablePAMTarget(ctx, tenantID, targetType, id, requester, "A276 approved ("+approval.ID+"): "+reason); err != nil {
				return api.PAMAccountFlag{}, err
			}
		}
	}
	payload := projections.PAMAccountFlagActioned{TargetType: targetType, TargetID: id, Action: req.Action, OwnerID: req.OwnerID, RotationID: rotationID,
		Reason: reason, Approval: use, Actor: requester, At: s.clock().UTC().Truncate(time.Microsecond)}
	data, err := json.Marshal(payload)
	if err != nil {
		return api.PAMAccountFlag{}, err
	}
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := s.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, use, s.clock().UTC()); err != nil {
			return err
		}
		candidate := events.Event{ID: eventID, Type: projections.EventPAMAccountFlagActioned, TenantID: tenantID, Time: payload.At, Data: data}
		if actor, ok := events.ActorFromContext(ctx); ok {
			candidate.Actor = &actor
		}
		canonical, err := s.log.Append(ctx, candidate)
		if err != nil {
			return err
		}
		if canonical.Type != candidate.Type || canonical.TenantID != tenantID || !bytes.Equal(canonical.Data, data) {
			return fmt.Errorf("%w: canonical account action differs", orchestrator.ErrIdempotencyConflict)
		}
		return s.projector.ApplyTx(ctx, tx, canonical)
	}); err != nil {
		return api.PAMAccountFlag{}, err
	}
	flag, err = s.store.GetPAMAccountFlag(ctx, tenantID, targetType, id)
	return flagView(flag), err
}

// The served broker's methods.

func (s *Server) ListPAMAccountFlags(ctx context.Context, tenantID, status string) ([]api.PAMAccountFlag, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMAccountFlags(ctx, tenantID, status)
}

func (s *Server) ScanPAMAccountFlags(ctx context.Context, tenantID string) ([]api.PAMAccountFlag, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ScanPAMAccountFlags(ctx, tenantID)
}

func (s *Server) RequestPAMAccountAction(ctx context.Context, tenantID, requester, targetType, id string, req api.PAMAccountActionRequest) (api.PAMAccountActionReview, error) {
	if s.pam == nil {
		return api.PAMAccountActionReview{}, api.ErrPAMUnavailable
	}
	return s.pam.RequestPAMAccountAction(ctx, tenantID, requester, targetType, id, req)
}

func (s *Server) PlanPAMAccountAction(ctx context.Context, tenantID, requester, targetType, id string, req api.PAMAccountActionRequest) (api.PAMAccountActionPlan, error) {
	if s.pam == nil {
		return api.PAMAccountActionPlan{}, api.ErrPAMUnavailable
	}
	return s.pam.PlanPAMAccountAction(ctx, tenantID, requester, targetType, id, req)
}

func (s *Server) ApplyPAMAccountAction(ctx context.Context, tenantID, requester, targetType, id string, req api.PAMAccountActionRequest, rotationID string) (api.PAMAccountFlag, error) {
	if s.pam == nil {
		return api.PAMAccountFlag{}, api.ErrPAMUnavailable
	}
	return s.pam.ApplyPAMAccountAction(ctx, tenantID, requester, targetType, id, req, rotationID)
}
