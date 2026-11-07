// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/servicedependents"
)

// EffectiveServiceDependentStepTx follows deterministic projected replacements.
// Callers that authorize I/O additionally verify the immutable source head.
func (s *Store) EffectiveServiceDependentStepTx(ctx context.Context, tx pgx.Tx, tenantID, rotationID, rootStepID string) (ServiceDependentStep, error) {
	head, err := s.GetServiceDependentStepTx(ctx, tx, tenantID, rotationID, rootStepID)
	if err != nil {
		return head, err
	}
	if head.Intent.Recovery != nil {
		return head, ErrIdempotencyConflict
	}
	for depth := 0; depth < servicedependents.MaxInverseRecoveryDepth; depth++ {
		next, err := s.GetServiceDependentStepTx(ctx, tx, tenantID, rotationID, servicedependents.RecoveryStepID(rotationID, head.Intent.ID))
		if errors.Is(err, ErrServiceDependentStepNotFound) {
			return head, nil
		}
		if err != nil {
			return head, err
		}
		if next.Intent.Recovery == nil || next.Intent.Recovery.RootStepID != rootStepID || next.Intent.Recovery.PreviousStepID != head.Intent.ID {
			return head, ErrIdempotencyConflict
		}
		head = next
	}
	return head, errors.New("store: retained native recovery history reached bounded capacity")
}
func (s *Store) ApplyServiceDependentStepRecoveryQueuedTx(ctx context.Context, tx pgx.Tx, tenantID string, previous, next servicedependents.RotationStep, previousStatus, reportDigest string, at time.Time) error {
	if previous.Validate() != nil || next.Validate() != nil || next.Recovery == nil || next.Direction != servicedependents.Inverse || next.Recovery.PreviousStepID != previous.ID || at.IsZero() {
		return errors.New("store: exact inverse recovery authority required")
	}
	parent, err := s.GetServiceDependentRotationTx(ctx, tx, tenantID, next.RotationID)
	if err != nil {
		return err
	}
	if parent.Direction != servicedependents.Inverse || !parent.DirectoryRestored || parent.IntentDigest != next.PlanDigest {
		return errors.New("store: native directory restoration precedes dependent recovery")
	}
	if existing, err := s.GetServiceDependentStepTx(ctx, tx, tenantID, parent.ID, next.ID); err == nil {
		a, _ := json.Marshal(existing.Intent)
		b, _ := json.Marshal(next)
		if crypto.SHA256Hex(a) != crypto.SHA256Hex(b) {
			return ErrIdempotencyConflict
		}
		return nil
	} else if !errors.Is(err, ErrServiceDependentStepNotFound) {
		return err
	}
	head, err := s.EffectiveServiceDependentStepTx(ctx, tx, tenantID, parent.ID, next.Recovery.RootStepID)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(head.Intent)
	b, _ := json.Marshal(previous)
	if head.Intent.ID != previous.ID || crypto.SHA256Hex(a) != crypto.SHA256Hex(b) || head.Status != previousStatus {
		return ErrIdempotencyConflict
	}
	observedDigest := ""
	if head.Report != nil {
		raw, err := json.Marshal(head.Report)
		if err != nil {
			return err
		}
		observedDigest = crypto.SHA256Hex(raw)
	}
	if observedDigest != reportDigest || head.Status == "succeeded" || head.Status == "queued" && !at.After(previous.Deadline.Add(time.Minute)) {
		return errors.New("store: current inverse work does not need replacement")
	}
	current, err := s.NextServiceDependentStepTx(ctx, tx, parent, false)
	if err != nil && !errors.Is(err, ErrServiceDependentStepFailed) {
		return err
	}
	if current == nil || current.ID != previous.ID {
		return errors.New("store: recovery is outside the retained inverse order")
	}
	child, err := scanSecretStaticRotationCommand(tx.QueryRow(ctx, "SELECT "+secretStaticRotationColumns+" FROM secret_static_rotation_commands WHERE tenant_id=$1 AND id=$2 FOR UPDATE", tenantID, parent.CommandID))
	if err != nil {
		return err
	}
	historical := !at.After(child.UpdatedAt) && secretStaticRotationPhaseRank(child.Phase) >= secretStaticRotationPhaseRank(SecretStaticRotationPrepared)
	if child.DependentChangeID != parent.ID || child.RequestBinding != parent.IntentDigest || !historical && child.Phase != SecretStaticRotationPrepared && child.Phase != SecretStaticRotationStaged && child.Phase != SecretStaticRotationCutover {
		return errors.New("store: inverse recovery has no exact recoverable sealed child")
	}
	if head.OutboxID != nil {
		_, err = tx.Exec(ctx, `UPDATE outbox SET status='cancelled',worker_id=NULL,lease_until=NULL,
 claimed_by_agent_id=NULL,claim_expires_at=NULL,claim_completed_at=COALESCE(claim_completed_at,$4)
 WHERE tenant_id=$1 AND id=$2 AND destination=$3 AND status IN ('pending','claimed')`, tenantID, *head.OutboxID, servicedependents.RotationDestination, at)
		if err != nil {
			return err
		}
	}
	return s.insertServiceDependentStepTx(ctx, tx, tenantID, parent, next, at)
}
