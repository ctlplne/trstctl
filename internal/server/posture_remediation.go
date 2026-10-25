// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
)

// Automatic remediation of posture findings (A47).
//
// A tenant posture rule may ask for a remediation. The scheduler evaluates
// each deployed X.509 identity's served certificate against the tenant's
// active module and, for a violation that asks to renew, queues the same
// renewal transition an expiry-driven decision would, with the rule named in
// the reason. It runs under the automation switch and the maintenance
// deferral the expiry scheduler uses, is bounded per tenant per sweep, skips
// identities with renewal work in flight or an unverified delivery, and
// stays idempotent because an identity already renewing refuses a second
// transition.

const (
	postureRemediationPerTenantLimit = 100
	postureRemediationReasonPrefix   = "posture:"
)

// runPostureRemediationOnce queues renewals for posture violations that ask
// for them and reports how many it queued.
func (s *Server) runPostureRemediationOnce(ctx context.Context, now time.Time) (int, error) {
	if s.postureEvaluator == nil || s.store == nil || s.orch == nil {
		return 0, nil
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, tenant := range tenants {
		n, err := s.remediateTenantPosture(ctx, tenant.TenantID, now)
		queued += n
		if err != nil {
			return queued, err
		}
	}
	return queued, nil
}

func (s *Server) remediateTenantPosture(ctx context.Context, tenantID string, now time.Time) (int, error) {
	if _, _, err := s.postureEvaluator.ActiveModule(ctx, tenantID); err != nil {
		// No active module for this tenant: nothing asks for remediation.
		return 0, nil
	}
	rows, err := s.store.ListLifecycleAutomationInventory(ctx, tenantID, 500)
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, row := range rows {
		if queued >= postureRemediationPerTenantLimit {
			break
		}
		if row.IdentityStatus != string(orchestrator.StateDeployed) || row.PendingRenewal || row.DeliveryUnverified ||
			strings.TrimSpace(row.CertificateFingerprint) == "" {
			continue
		}
		cert, err := s.store.GetCertificateByFingerprint(ctx, tenantID, row.CertificateFingerprint)
		if err != nil {
			continue
		}
		if cert.Status == "revoked" || cert.Status == "superseded" {
			continue
		}
		violations, err := s.postureEvaluator.EvaluatePosture(ctx, policy.Input{
			Action: policy.ActionCertificatePosture, TenantID: tenantID, Subject: cert.ID,
			Certificate: api.CertificatePostureFacts(cert, now),
		})
		if err != nil {
			// A rule that cannot be evaluated queues nothing; the listing
			// counts the error, and a stuck module must not stall the sweep.
			continue
		}
		rule := postureRenewalRule(violations)
		if rule == "" {
			continue
		}
		if ident, err := s.store.GetIdentity(ctx, tenantID, row.IdentityID); err == nil {
			if _, paused := orchestrator.RenewalPausedTarget(ident); paused {
				// B4-8: a posture rule does not override an operator's rollback pause.
				continue
			}
		}
		reason := postureRemediationReasonPrefix + rule
		payload, err := json.Marshal(transitionTrigger{
			IdentityID: row.IdentityID, To: string(orchestrator.StateRenewing), Reason: reason,
			Origin: lifecycleTransitionOriginScheduler, PredecessorFingerprint: cert.Fingerprint,
		})
		if err != nil {
			return queued, err
		}
		if err := s.orch.TransitionWithSideEffectPayload(ctx, tenantID, row.IdentityID, orchestrator.StateRenewing, reason, payload); err != nil {
			if errors.Is(err, store.ErrIdentityEnrollmentConflict) || errors.Is(err, orchestrator.ErrInvalidTransition) ||
				errors.Is(err, orchestrator.ErrRenewalWorkPending) {
				continue
			}
			return queued, err
		}
		if s.logger != nil {
			s.logger.Info("posture remediation queued renewal", slog.String("tenant_id", tenantID),
				slog.String("identity_id", row.IdentityID), slog.String("rule", rule))
		}
		queued++
	}
	return queued, nil
}

// runNHIPostureAutomationOnce acts on the tenants' nhi_posture rules that ask
// for revoke or right_size (A100): through the lifecycle gate and the
// right-size playbook, bounded per tenant, each action a playbook run. One
// tenant's failure is logged and does not stall the others.
func (s *Server) runNHIPostureAutomationOnce(ctx context.Context, now time.Time) (api.NHIPostureAutomationResult, error) {
	var total api.NHIPostureAutomationResult
	if s.api == nil || s.store == nil {
		return total, nil
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return total, err
	}
	var errs []error
	for _, tenant := range tenants {
		r, err := s.api.RunNHIPostureAutomation(ctx, tenant.TenantID, now)
		total.Revoked += r.Revoked
		total.RightSized += r.RightSized
		total.Refused += r.Refused
		total.Skipped += r.Skipped
		if err != nil {
			errs = append(errs, err)
			if s.logger != nil {
				s.logger.Warn("NHI posture automation failed for a tenant", slog.String("tenant_id", tenant.TenantID), slog.String("error", err.Error()))
			}
		}
		if s.logger != nil && r.Revoked+r.RightSized+r.Refused > 0 {
			s.logger.Info("NHI posture automation acted", slog.String("tenant_id", tenant.TenantID),
				slog.Int("revoked", r.Revoked), slog.Int("right_sized", r.RightSized), slog.Int("refused", r.Refused))
		}
	}
	return total, errors.Join(errs...)
}

// postureRenewalRule names the first violation (rules are sorted) that asks
// for a renewal, or "" when none does.
func postureRenewalRule(violations []policy.PostureViolation) string {
	for _, v := range violations {
		if v.Remediation == policy.PostureRemediationRenew {
			return v.Rule
		}
	}
	return ""
}

// runRiskAcceptanceExpiryOnce reopens every tenant's accepted risks whose
// acceptance has expired (A106), whatever the automation switch says: expiry
// is the acceptance's own term, not an automatic remediation. One tenant's
// failure is logged and does not stall the others.
func (s *Server) runRiskAcceptanceExpiryOnce(ctx context.Context, now time.Time) int {
	if s.orch == nil || s.store == nil {
		return 0
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("risk acceptance expiry sweep could not list tenants", slog.String("error", err.Error()))
		}
		return 0
	}
	total := 0
	for _, tenant := range tenants {
		n, err := s.orch.ExpireRiskAcceptances(ctx, tenant.TenantID, now)
		total += n
		if err != nil && s.logger != nil {
			s.logger.Warn("risk acceptance expiry failed for a tenant", slog.String("tenant_id", tenant.TenantID), slog.String("error", err.Error()))
		}
		if n > 0 && s.logger != nil {
			s.logger.Info("risk acceptances expired; findings reopened", slog.String("tenant_id", tenant.TenantID), slog.Int("reopened", n))
		}
	}
	return total
}

// runProfilePostureOnce reconciles every tenant's certificate-profile RSA
// floor findings with its active profiles (batch 14): a profile created while
// the finding could not be recorded, or one raised since, converges here. One
// tenant's failure is logged and does not stall the others.
func (s *Server) runProfilePostureOnce(ctx context.Context) int {
	if s.orch == nil || s.store == nil {
		return 0
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("profile posture sweep could not list tenants", slog.String("error", err.Error()))
		}
		return 0
	}
	total := 0
	for _, tenant := range tenants {
		n, err := s.orch.ReconcileProfileRSAFloorPosture(ctx, tenant.TenantID)
		total += n
		if err != nil && s.logger != nil {
			s.logger.Warn("profile posture sweep failed for a tenant", slog.String("tenant_id", tenant.TenantID), slog.String("error", err.Error()))
		}
	}
	return total
}
