// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"strings"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
)

// Rolling back a deploy the listener never accepted (epic D2 + D4).
//
// This is the pair that makes verification worth having. Detection alone tells
// an operator that production is serving the wrong certificate; it does not
// stop production serving the wrong certificate. D4 built the executed re-bind
// and could only be triggered by hand, because nothing could yet decide
// automatically that a re-bind was warranted. `verify_failed` is that decision.
//
// It fires only on verify_failed and never on plain failure, and the difference
// is load-bearing: a deploy that FAILED did not change the target, so rolling
// it back would undo something that was never done — at best a no-op, at worst
// a re-bind away from a certificate that is serving perfectly well.
//
// OPT-IN, per target, default off.
//
// Automatic re-binding of a production listener is a mutation an operator did
// not ask for at the moment it happens, and this codebase's habit is that
// consent for one thing is not consent for another: enabling verification says
// "tell me when this breaks", not "change my load balancer when you think it
// has". An operator who wants the loop closed says so on the target, and the
// receipt records that they did.

// autoRollbackConfigKey is the deployment-target config flag that opts a target
// into automatic rollback on verification failure.
const autoRollbackConfigKey = "auto_rollback_on_verify_failure"

// maybeAutoRollbackAfterVerifyFailure queues a rollback when a deploy applied
// but the listener is not serving it.
//
// Everything it needs comes from the job payload the control plane itself
// queued — never from the agent's report. An agent that could name the target
// in its result could trigger a re-bind of a target it was never given.
func (a *agentService) maybeAutoRollbackAfterVerifyFailure(ctx context.Context, tenantID string, jobID int64) {
	if a.store == nil || a.orch == nil {
		return
	}
	payload, _, err := a.store.AgentJobPayload(ctx, tenantID, jobID)
	if err != nil || len(payload) == 0 {
		return
	}
	var intent relay.DeployIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		return
	}
	if strings.TrimSpace(intent.TargetID) == "" {
		return
	}

	target, err := a.store.GetDeploymentTarget(ctx, tenantID, intent.TargetID)
	if err != nil {
		return
	}
	if !autoRollbackEnabled(target.Config) {
		// The operator has not asked for this. Detection already alerted; doing
		// more without being asked would be the platform deciding on its own to
		// change a production listener.
		return
	}
	// Only families whose API can address an installed object separately from
	// uploading one can re-bind at all (D4). For the rest there is nothing to
	// automate, and pretending otherwise would queue work that fails.
	if !connector.CanRollback(target.Type) {
		return
	}

	predecessor := a.store.ResolvePredecessorCertificate(ctx, tenantID, intent.IdentityID)
	if predecessor.Fingerprint == "" {
		// No predecessor means there is nothing to roll back TO. A first
		// deployment that fails verification is a deployment to fix, not a
		// state to restore.
		return
	}

	route := strings.TrimSpace(intent.Target)
	if route == "" {
		route = target.Name
	}
	_, _ = a.orch.RequestConnectorRollback(ctx, tenantID, orchestrator.ConnectorRollbackRequest{
		Connector: target.Type, Target: route, TargetID: target.ID,
		IdentityID: intent.IdentityID, TargetConfig: target.Config,
		PredecessorFingerprint: predecessor.Fingerprint,
		PredecessorSerial:      predecessor.Serial,
		// The reason travels into the receipt so an operator reading the
		// evidence chain later sees WHY a rollback they did not request
		// happened, and can tell it from one they did.
		Reason: "automatic rollback: post-deploy verification found the listener serving a different certificate",
	})
}

// autoRollbackEnabled reads the opt-in flag from a target's operator-owned
// config.
//
// Absent means off. A missing flag is not consent, and a target whose config
// predates this feature must never start re-binding itself because a new
// version shipped.
func autoRollbackEnabled(cfg json.RawMessage) bool {
	if len(cfg) == 0 {
		return false
	}
	var fields map[string]any
	if err := json.Unmarshal(cfg, &fields); err != nil {
		return false
	}
	v, ok := fields[autoRollbackConfigKey]
	if !ok {
		return false
	}
	enabled, ok := v.(bool)
	return ok && enabled
}
