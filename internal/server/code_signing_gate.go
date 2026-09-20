// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/codesign"
	"trstctl.com/trstctl/internal/policy"
)

const codeSigningApprovalAction = "sign"

// servedCodeSigningGate adapts the same live, audited OPA evaluator and
// tenant-scoped distinct-approver store used by the served mutation gate. It is
// intentionally assembled at Build time, after the policy bulkhead exists; a
// library-only Gate placed in a test registry is not production wiring.
type servedCodeSigningGate struct {
	policy          api.PolicyEvaluator
	approvals       api.ApprovalChecker
	requireApproval bool
}

var _ codesign.Gate = (*servedCodeSigningGate)(nil)
var _ api.ExactApprovalChecker = (*servedCodeSigningGate)(nil)

func codeSigningGateFromMutationGate(g api.MutationGate) codesign.Gate {
	if g.Policy == nil && !g.RequireApproval {
		return nil
	}
	return &servedCodeSigningGate{
		policy: g.Policy, approvals: g.Checker, requireApproval: g.RequireApproval,
	}
}

func (g *servedCodeSigningGate) MaySign(ctx context.Context, tenantID, principal, keyID, digestHex string) (bool, string) {
	if g == nil {
		return false, "code-signing gate is unavailable"
	}
	if g.policy != nil {
		decision, err := g.policy.Evaluate(ctx, policy.Input{
			Action: policy.ActionCodeSign, TenantID: tenantID, Subject: keyID, Actor: principal,
			Attrs: map[string]any{"key_id": keyID, "digest_sha256": digestHex},
		})
		switch {
		case err != nil:
			return false, "code-signing policy evaluation failed closed"
		case !decision.Allow:
			if decision.Reason == "" {
				return false, "code-signing policy denied the request"
			}
			return false, decision.Reason
		}
	}
	return true, ""
}

// CodeSigningApprovalRequired lets the durable command path move dual control
// ahead of command/outbox creation. MaySign remains the worker-time policy
// recheck; a merely pending review must never become a terminal worker failure.
func (g *servedCodeSigningGate) CodeSigningApprovalRequired() bool {
	return g != nil && g.requireApproval
}

// AuthorizeApproval delegates to the generic immutable request authority. The
// durable code-signing service supplies the exact command/key binding and embeds
// the returned use in codesign.commanded for transactional consumption.
func (g *servedCodeSigningGate) AuthorizeApproval(ctx context.Context, intent api.ApprovalIntent) (api.ApprovalAuthority, bool, string) {
	if g == nil || g.approvals == nil {
		return api.ApprovalAuthority{}, false, "code-signing approval is required but no approval store is configured"
	}
	exact, ok := g.approvals.(api.ExactApprovalChecker)
	if !ok {
		return api.ApprovalAuthority{}, false, "code-signing approval store does not support exact single-use authority"
	}
	return exact.AuthorizeApproval(ctx, intent)
}
