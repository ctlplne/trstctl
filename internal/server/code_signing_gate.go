// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/codesign"
	"trstctl.com/trstctl/internal/crypto"
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
	if g.requireApproval {
		resource := codeSigningApprovalResource(principal, keyID, digestHex)
		if g.approvals == nil {
			return false, "code-signing approval is required but no approval store is configured"
		}
		approved, reason := g.approvals.IsApproved(ctx, tenantID, resource, codeSigningApprovalAction, principal)
		if !approved {
			if reason == "" {
				reason = "the requested signature lacks distinct-approver authorization"
			}
			return false, fmt.Sprintf("%s (approval resource %s, action %s)", reason, resource, codeSigningApprovalAction)
		}
	}
	return true, ""
}

// codeSigningApprovalResource binds an approval to the authenticated requester,
// one key-or-keyless identity, and one exact SHA-256 artifact digest without
// placing those raw values in an approval URL. Tenant and action are separate
// store keys.
func codeSigningApprovalResource(principal, keyID, digestHex string) string {
	return "codesign:" + crypto.SHA256Hex([]byte(principal+"\x00"+keyID+"\x00"+digestHex))
}
