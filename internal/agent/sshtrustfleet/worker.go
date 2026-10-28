// SPDX-License-Identifier: BUSL-1.1

// Package sshtrustfleet runs one additive, host-authorized SSH trust command.
// Claim scheduling and signed receipt delivery remain in the agent channel.
package sshtrustfleet

import (
	"context"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/agent/sshtrust"
	"trstctl.com/trstctl/internal/sshtrustrollout"
)

const WorkTimeout = 30 * time.Second
const LeaseSeconds = 120

// ClaimableKinds is the dedicated SSH worker's actual claim list. The shared
// relay loop must never lease this work or consume its independent bulkhead.
func ClaimableKinds() []string { return []string{sshtrustrollout.Destination} }

// Execute receives only host-local configuration and authority from its caller.
// Remote payloads cannot supply paths, argv, confirmation or a replacement CA pin.
func Execute(ctx context.Context, tenantID string, config sshtrust.Config, local sshtrustrollout.LocalAuthority, command sshtrustrollout.Command) (sshtrustrollout.Report, error) {
	return ExecuteAt(ctx, tenantID, config, local, command, time.Now().UTC())
}

// ExecuteAt uses the authenticated claim's server-time estimate for the finite
// execution window. Duration-based deadlines keep a skewed host wall clock from
// extending that window; the agent's local clock remains observation metadata.
func ExecuteAt(ctx context.Context, tenantID string, config sshtrust.Config, local sshtrustrollout.LocalAuthority, command sshtrustrollout.Command, serverNow time.Time) (sshtrustrollout.Report, error) {
	report := sshtrustrollout.Report{RolloutID: command.RolloutID, AgentID: command.AgentID, PlanDigest: command.PlanDigest, ReadinessDigest: command.ReadinessDigest, CAFingerprint: command.CAFingerprint, State: "refused", ReasonCode: "local_configuration_invalid", Phase: "preflight", Rollback: "not_needed", CheckedAt: time.Now().UTC()}
	if err := ctx.Err(); err != nil {
		report.ReasonCode = "canceled"
		return report, err
	}
	if err := command.PermitLocal(local, serverNow); err != nil {
		var refusal *sshtrustrollout.Refusal
		if errors.As(err, &refusal) {
			report.ReasonCode = refusal.Code
		}
		return report, err
	}
	applier, err := sshtrust.New(tenantID, config, nil)
	if err != nil {
		return report, err
	}
	work, cancel := context.WithTimeout(ctx, WorkTimeout)
	defer cancel()
	work, cancelDeadline := context.WithTimeout(work, command.ExpiresAt.Sub(serverNow))
	defer cancelDeadline()
	observed, err := applier.AddCATrustObserved(work, command.PublicCAKey)
	report.State = "failed"
	report.ReasonCode = "apply_failed"
	if observed.Phase == "readback" {
		report.ReasonCode = "readback_failed"
	}
	if err == nil {
		report.State = "verified"
		report.ReasonCode = ""
	}
	report.Phase = observed.Phase
	report.Rollback = observed.Rollback
	report.Changed = observed.Changed
	report.CAReadBack = observed.CAReadBack
	report.EffectiveConfigReadBack = observed.EffectiveConfigReadBack
	report.TrustFileSHA256 = observed.TrustFileSHA256
	report.ConfigFileSHA256 = observed.ConfigFileSHA256
	report.Validated = observed.Validated
	report.Reloaded = observed.Reloaded
	report.Healthy = observed.Healthy
	report.CheckedAt = time.Now().UTC()
	return report, err
}
