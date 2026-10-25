// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// rotateVerificationPoll bounds how long a waiting credential rotation sleeps
// between looks at its replacement's verification; the deadline caps it.
const rotateVerificationPoll = 30 * time.Second

// rotateScope is the part of a credential-rotate run's recorded scope the
// verification command acts on.
type rotateScope struct {
	OriginalIdentityID    string    `json:"replaced_identity_id"`
	ReplacementIdentityID string    `json:"replacement_identity_id"`
	RevocationReason      string    `json:"revocation_reason"`
	VerifyBy              time.Time `json:"verify_by"`
}

func decodeRotateScope(raw json.RawMessage) (rotateScope, error) {
	var scope rotateScope
	if err := json.Unmarshal(raw, &scope); err != nil {
		return rotateScope{}, fmt.Errorf("server: decode credential-rotate scope: %w", err)
	}
	if scope.OriginalIdentityID == "" || scope.ReplacementIdentityID == "" || scope.VerifyBy.IsZero() ||
		!crypto.IsValidRevocationReason(scope.RevocationReason) ||
		scope.RevocationReason == string(crypto.RevocationReasonRemoveFromCRL) ||
		scope.RevocationReason == string(crypto.RevocationReasonKeyCompromise) {
		return rotateScope{}, errors.New("server: credential-rotate scope is incomplete")
	}
	return scope, nil
}

// handleRotateVerification drives one credential-rotate run (owner decision,
// batch 14). The playbook issued a replacement and returned. This command
// waits, without spending its retry budget, for the replacement's signed and
// verified delivery: the signature-verified endpoint receipt the incident
// fleet gate also reads. Only then is the replacement marked deployed and the
// original revoked. A signed verify_failed receipt, or a deadline that passes
// first, keeps the original valid and records a finding naming the
// replacement and its target.
func (d *issuanceDispatcher) handleRotateVerification(ctx context.Context, m orchestrator.Message) error {
	var command orchestrator.RotateVerificationCommand
	if err := json.Unmarshal(m.Payload, &command); err != nil || command.RunID == "" {
		return fmt.Errorf("server: credential-rotate command requires run_id")
	}
	run, err := d.store.GetRemediationPlaybookRun(ctx, m.TenantID, command.RunID)
	if err != nil {
		return err
	}
	if run.Action != "rotate" {
		return fmt.Errorf("server: run %s is not a credential rotation", run.ID)
	}
	if run.Status != orchestrator.RotateRunRunning {
		return nil
	}
	scope, err := decodeRotateScope(run.ScopeDelta)
	if err != nil {
		return err
	}
	verification, found, err := d.store.LatestSignedDeliveryVerification(ctx, m.TenantID, scope.ReplacementIdentityID)
	if err != nil {
		return err
	}
	if found && verification.Status == "verified" {
		return d.completeVerifiedRotation(ctx, m.TenantID, run, scope, verification)
	}
	if found && verification.Status == "verify_failed" {
		return d.keepOriginalAfterRotation(ctx, m.TenantID, run, scope, orchestrator.RotatePhaseVerifyFailedKept,
			"the replacement was delivered, but a signed verification found its endpoint not serving it; the original stays valid",
			verification.UpdatedAt, "verification:"+verification.ID)
	}
	now := time.Now().UTC()
	if d.rotateNow != nil {
		now = d.rotateNow().UTC()
	}
	if !now.Before(scope.VerifyBy) {
		return d.keepOriginalAfterRotation(ctx, m.TenantID, run, scope, orchestrator.RotatePhaseUnverifiedKept,
			"no signed, verified delivery of the replacement arrived by "+scope.VerifyBy.Format(time.RFC3339)+"; the original stays valid",
			scope.VerifyBy, "")
	}
	resume := now.Add(rotateVerificationPoll)
	if resume.After(scope.VerifyBy) {
		resume = scope.VerifyBy
	}
	return orchestrator.DeferDeliveryUntil(fmt.Errorf("server: credential rotation %s waits for the replacement's signed verification", run.ID), resume)
}

// completeVerifiedRotation records the deployed edge the signed receipt
// proved, then revokes the original. Each step reads current state first, so
// a retry after any of them converges.
func (d *issuanceDispatcher) completeVerifiedRotation(ctx context.Context, tenantID string, run store.RemediationPlaybookRun,
	scope rotateScope, verification store.ConnectorDeliveryReceipt) error {
	replacement, err := d.orch.State(ctx, tenantID, scope.ReplacementIdentityID)
	if err != nil {
		return err
	}
	if replacement == orchestrator.StateIssued {
		if err := d.orch.TransitionAfterCompletedSideEffect(ctx, tenantID, scope.ReplacementIdentityID, orchestrator.StateDeployed,
			"credential-rotate replacement deployed after its signed verification: "+run.Reason, "connector.deploy"); err != nil {
			return err
		}
	}
	original, err := d.orch.State(ctx, tenantID, scope.OriginalIdentityID)
	if err != nil {
		return err
	}
	if original != orchestrator.StateRevoked && original != orchestrator.StateRetired {
		if err := d.orch.TransitionWithIdempotency(ctx, tenantID, scope.OriginalIdentityID, orchestrator.StateRevoked,
			scope.RevocationReason, orchestrator.RotateVerificationIdempotencyKey(run.ID)+":revoke"); err != nil {
			return err
		}
	}
	run.Status, run.Phase = orchestrator.RotateRunExecuted, orchestrator.RotatePhaseVerifiedAndRevoked
	run.EvidenceRefs = append(run.EvidenceRefs, "verification:"+verification.ID, "state:"+string(orchestrator.StateRevoked))
	_, err = d.orch.RecordRotatePlaybookRun(ctx, tenantID, run)
	return err
}

// keepOriginalAfterRotation ends a run without revoking anything. The finding
// is recorded first: once the run is terminal, a retry stops here.
func (d *issuanceDispatcher) keepOriginalAfterRotation(ctx context.Context, tenantID string, run store.RemediationPlaybookRun,
	scope rotateScope, phase, detail string, observedAt time.Time, evidence string) error {
	if err := d.orch.RecordRotationUnverified(ctx, tenantID, orchestrator.RotationUnverified{
		RunID: run.ID, OriginalIdentityID: scope.OriginalIdentityID, ReplacementIdentityID: scope.ReplacementIdentityID,
		Connector: run.Connector, Target: run.Target, Outcome: phase, Detail: detail, ObservedAt: observedAt,
	}); err != nil {
		return err
	}
	run.Status, run.Phase, run.TerminalReason = orchestrator.RotateRunFailed, phase, detail
	if evidence != "" {
		run.EvidenceRefs = append(run.EvidenceRefs, evidence)
	}
	_, err := d.orch.RecordRotatePlaybookRun(ctx, tenantID, run)
	return err
}

// rotationAwaitingVerification reports whether an identity is the replacement
// of a credential-rotate run that still waits for its signed, verified
// delivery. While it waits, that run, not issuance or a host result, marks the
// replacement deployed.
func rotationAwaitingVerification(ctx context.Context, st *store.Store, tenantID string, attributes json.RawMessage) (bool, error) {
	if st == nil || len(attributes) == 0 {
		return false, nil
	}
	var attrs map[string]any
	if json.Unmarshal(attributes, &attrs) != nil {
		return false, nil
	}
	runID, _ := attrs[orchestrator.RotateReplacementRunAttribute].(string)
	if runID == "" {
		return false, nil
	}
	run, err := st.GetRemediationPlaybookRun(ctx, tenantID, runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return run.Action == "rotate" && run.Status == orchestrator.RotateRunRunning, nil
}
