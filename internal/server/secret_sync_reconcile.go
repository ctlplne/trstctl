// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

// Closed reasons recorded on reconciled outcomes. They never carry receiver
// response text (AN-8).
const (
	secretSyncReconciledAbsentError   = "receiver readback shows this command's value absent; a later command may deliver the current version"
	secretSyncOperatorAbsentError     = "operator verified at the destination that this command's value is absent"
	secretSyncSettledByReadbackDetail = "receiver readback matched this command's value after more than one receiver start"
	secretSyncSettledByOperatorDetail = "operator verified at the destination that this command's value is present"
)

// readBackSecretSyncReceiver opens this job's sealed command value inside the
// tenant key domain, asks the target to compare it with the receiver's current
// state under the same operation ID, and wipes the value. It never writes.
func (d *secretIntegrationOutboxDispatcher) readBackSecretSyncReceiver(ctx context.Context, tenantID string, job store.SecretSyncJob) (secretsync.ReceiverReconciliation, error) {
	target := d.secretSyncTarget(tenantID, job.Target)
	if target == nil {
		return secretsync.ReceiverStateUnknown, fmt.Errorf("server: secret-sync target %q is not configured for tenant", job.Target)
	}
	if !target.CanReconcile() {
		return secretsync.ReceiverStateUnknown, nil
	}
	if d.kek == nil || d.store == nil {
		return secretsync.ReceiverStateUnknown, errors.New("server: secret-sync readback requires the store and a KEK")
	}
	raw, err := d.store.SecretSyncOutboxPayload(ctx, tenantID, job.OutboxID, job.Target)
	if err != nil {
		return secretsync.ReceiverStateUnknown, fmt.Errorf("server: read secret-sync command for readback: %w", err)
	}
	var payload secretSyncOutboxPayload
	if err := json.Unmarshal(raw, &payload); err != nil || payload.ID != job.ID || payload.Key != job.RemoteKey || len(payload.Sealed) == 0 {
		return secretsync.ReceiverStateUnknown, errors.New("server: secret-sync command payload does not match its projected job")
	}
	value, err := openTenantValue(ctx, d.tenantCrypto, d.kek, tenantID, payload.Sealed, secretSyncAAD(tenantID, job.Target, payload.ID, payload.Key))
	if err != nil {
		return secretsync.ReceiverStateUnknown, fmt.Errorf("server: open secret-sync command for readback: %w", err)
	}
	defer secret.Wipe(value)
	if crypto.SHA256Hex(value) != job.ValueDigest {
		return secretsync.ReceiverStateUnknown, errors.New("server: secret-sync sealed payload digest does not match its projected command")
	}
	return target.ReconcileOperation(ctx, payload.ID, payload.Key, value)
}

// appendAndProjectSecretSyncSettled records the one settlement receipt for a
// delivered job and projects it. Replaying it is a no-op: the deterministic
// event ID is checked against the retained envelope before anything is written.
func (d *secretIntegrationOutboxDispatcher) appendAndProjectSecretSyncSettled(ctx context.Context, tenantID string, job store.SecretSyncJob, authority store.SecretSyncReceiverAuthority, method, actor, detail string) error {
	if d.store == nil || d.log == nil {
		return errors.New("server: secret-sync settlement requires store and event log")
	}
	if job.Status != store.SecretSyncJobDelivered || job.OutboxID <= 0 || job.TenantEpoch == "" {
		return fmt.Errorf("%w: secret-sync settlement needs a delivered command", store.ErrIdempotencyConflict)
	}
	payload := projections.SecretSyncReceiverSettled{
		ID: job.ID, TenantEpoch: job.TenantEpoch, OutboxID: job.OutboxID,
		ReceiverIOStarts: authority.ReceiverIOStarts, Method: method, Actor: actor, Detail: detail,
	}
	if err := projections.ValidateSecretSyncReceiverSettled(payload); err != nil {
		return err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	eventID := store.SecretSyncReceiverSettledEventID(tenantID, job.ID)
	return d.store.WithSecretSyncTerminalChoiceLock(ctx, tenantID, job.ID, func(lockCtx context.Context) error {
		canonical, found, err := d.log.EventByID(lockCtx, eventID)
		if err != nil {
			return err
		}
		if !found {
			candidate := events.Event{ID: eventID, Type: projections.EventSecretSyncReceiverSettled, TenantID: tenantID, SchemaVersion: 1, Data: data}
			if ctxActor, ok := events.ActorFromContext(lockCtx); ok {
				candidate.Actor = &ctxActor
			}
			canonical, err = d.log.Append(lockCtx, candidate)
			if err != nil {
				return err
			}
		}
		var retained projections.SecretSyncReceiverSettled
		if canonical.ID != eventID || canonical.Type != projections.EventSecretSyncReceiverSettled || canonical.TenantID != tenantID ||
			json.Unmarshal(canonical.Data, &retained) != nil || retained.ID != job.ID || retained.OutboxID != job.OutboxID {
			return fmt.Errorf("%w: retained secret-sync settlement differs from this command", store.ErrIdempotencyConflict)
		}
		return projections.New(d.store).Apply(lockCtx, canonical)
	})
}

// settleSecretSyncAfterDelivery closes the lane behind a command that needed
// more than one receiver start. A readback that matches is the independent
// proof; a target that cannot read back leaves the lane for the operator's
// reconcile command, and the job read says so.
func (d *secretIntegrationOutboxDispatcher) settleSecretSyncAfterDelivery(ctx context.Context, tenantID, jobID string) error {
	if d.store == nil || d.log == nil {
		return nil
	}
	job, err := d.store.GetSecretSyncJob(ctx, tenantID, jobID)
	if err != nil {
		return err
	}
	authority, err := d.store.SecretSyncReceiverAuthority(ctx, tenantID, jobID)
	if err != nil {
		return err
	}
	if job.Status != store.SecretSyncJobDelivered || authority.EffectState != store.SecretSyncReceiverEffectPossible || authority.ReceiverIOStarts <= 1 {
		return nil
	}
	state, err := d.readBackSecretSyncReceiver(ctx, tenantID, job)
	if err != nil || state != secretsync.ReceiverStateMatches {
		// Unknown or differing readback never settles by itself; the next
		// attempt or the operator's reconcile command decides.
		return nil
	}
	return d.appendAndProjectSecretSyncSettled(ctx, tenantID, job, authority, "readback", "", secretSyncSettledByReadbackDetail)
}

// ReconcileSecretSyncJob is the served reconciliation: it resolves a command
// whose receiver outcome is unproven without sending the value again. The
// closed outcome words are the API's contract.
func (d *secretIntegrationOutboxDispatcher) ReconcileSecretSyncJob(ctx context.Context, tenantID, jobID string, operatorVerified bool, observed, actor string) (api.SecretSyncReconcileOutcome, error) {
	if d.store == nil || d.log == nil {
		return api.SecretSyncReconcileOutcome{}, errors.New("server: secret-sync reconciliation requires store and event log")
	}
	job, err := d.store.GetSecretSyncJob(ctx, tenantID, jobID)
	if err != nil {
		return api.SecretSyncReconcileOutcome{}, err
	}
	authority, err := d.store.SecretSyncReceiverAuthority(ctx, tenantID, jobID)
	if err != nil {
		return api.SecretSyncReconcileOutcome{}, err
	}
	finish := func(outcome, detail string) (api.SecretSyncReconcileOutcome, error) {
		current, err := d.store.GetSecretSyncJob(ctx, tenantID, jobID)
		if err != nil {
			return api.SecretSyncReconcileOutcome{}, err
		}
		currentAuthority, err := d.store.SecretSyncReceiverAuthority(ctx, tenantID, jobID)
		if err != nil {
			return api.SecretSyncReconcileOutcome{}, err
		}
		return api.SecretSyncReconcileOutcome{Outcome: outcome, Detail: detail, Job: current, Authority: currentAuthority}, nil
	}
	attempts := authority.OutboxAttempts
	if attempts < job.Attempts {
		attempts = job.Attempts
	}
	if attempts < 1 {
		attempts = 1
	}
	switch job.Status {
	case store.SecretSyncJobFailed:
		return finish(api.SecretSyncReconcileTerminal, "the command already failed; review the target and queue a new sync")
	case store.SecretSyncJobDelivered:
		if authority.EffectState == store.SecretSyncReceiverEffectSettled || authority.ReceiverIOStarts <= 1 {
			return finish(api.SecretSyncReconcileSettled, "the delivered command already releases its target lane")
		}
		state, err := d.readBackSecretSyncReceiver(ctx, tenantID, job)
		if err != nil {
			return api.SecretSyncReconcileOutcome{}, err
		}
		switch state {
		case secretsync.ReceiverStateMatches:
			if err := d.appendAndProjectSecretSyncSettled(ctx, tenantID, job, authority, "readback", actor, secretSyncSettledByReadbackDetail); err != nil {
				return api.SecretSyncReconcileOutcome{}, err
			}
			return finish(api.SecretSyncReconcileSettled, secretSyncSettledByReadbackDetail)
		case secretsync.ReceiverStateDiffers:
			return finish(api.SecretSyncReconcileDiverged, "the destination now holds a different value than this delivered command; queue a new sync for the current version instead of settling this one")
		}
		if operatorVerified && observed == "value_present" {
			if err := d.appendAndProjectSecretSyncSettled(ctx, tenantID, job, authority, "operator", actor, secretSyncSettledByOperatorDetail); err != nil {
				return api.SecretSyncReconcileOutcome{}, err
			}
			return finish(api.SecretSyncReconcileSettled, secretSyncSettledByOperatorDetail)
		}
		if operatorVerified {
			return finish(api.SecretSyncReconcileDiverged, "a delivered command cannot be marked absent; queue a new sync for the current version")
		}
		return finish(api.SecretSyncReconcileUnknown, "this target cannot read its receiver back; check the destination yourself and repeat with operator_verified and observed set")
	case store.SecretSyncJobPending:
	default:
		return api.SecretSyncReconcileOutcome{}, fmt.Errorf("server: secret-sync job has invalid projected status %q", job.Status)
	}
	switch authority.EffectState {
	case store.SecretSyncReceiverNoEffect:
		return finish(api.SecretSyncReconcileNotStarted, "no receiver start is recorded; the worker has not contacted the destination for this command")
	case store.SecretSyncReceiverFailureAuthorized, store.SecretSyncReceiverFailureReconciled:
		return finish(api.SecretSyncReconcileTerminal, "failure authority is recorded; the worker finalizes this command on its next pass")
	}
	state, err := d.readBackSecretSyncReceiver(ctx, tenantID, job)
	if err != nil {
		return api.SecretSyncReconcileOutcome{}, err
	}
	if state == secretsync.ReceiverStateUnknown && operatorVerified {
		switch observed {
		case "value_present":
			state = secretsync.ReceiverStateMatches
		case "value_absent":
			state = secretsync.ReceiverStateDiffers
		}
	}
	switch state {
	case secretsync.ReceiverStateMatches:
		if err := d.appendAndProjectSecretSyncEvidence(ctx, store.SecretSyncDeliveredEventID(tenantID, job.ID), tenantID,
			projections.EventSecretSyncDelivered, projections.SecretSyncDelivered{ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: attempts}); err != nil {
			return api.SecretSyncReconcileOutcome{}, err
		}
		if authority.ReceiverIOStarts > 1 {
			delivered, err := d.store.GetSecretSyncJob(ctx, tenantID, jobID)
			if err != nil {
				return api.SecretSyncReconcileOutcome{}, err
			}
			method, detail := "readback", secretSyncSettledByReadbackDetail
			if operatorVerified {
				method, detail = "operator", secretSyncSettledByOperatorDetail
			}
			if err := d.appendAndProjectSecretSyncSettled(ctx, tenantID, delivered, authority, method, actor, detail); err != nil {
				return api.SecretSyncReconcileOutcome{}, err
			}
		}
		return finish(api.SecretSyncReconcileDelivered, "the destination holds this command's value; the command is delivered and its lane released")
	case secretsync.ReceiverStateDiffers:
		closedError := secretSyncReconciledAbsentError
		if operatorVerified {
			closedError = secretSyncOperatorAbsentError
		}
		authorized, err := d.store.AuthorizeSecretSyncReconciledNoEffect(ctx, tenantID, job.ID, job.OutboxID, closedError, attempts)
		if err != nil {
			return api.SecretSyncReconcileOutcome{}, err
		}
		if !authorized {
			return finish(api.SecretSyncReconcileTerminal, "the command left the pending state while reconciling; read it again")
		}
		if err := d.appendAndProjectSecretSyncEvidence(ctx, store.SecretSyncFailedEventID(tenantID, job.ID), tenantID,
			projections.EventSecretSyncFailed, projections.SecretSyncFailed{ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: attempts, Error: closedError}); err != nil {
			return api.SecretSyncReconcileOutcome{}, err
		}
		return finish(api.SecretSyncReconcileFailed, closedError)
	}
	return finish(api.SecretSyncReconcileUnknown, "this target cannot read its receiver back and the worker's last attempt was ambiguous; check the destination yourself and repeat with operator_verified and observed set")
}

var _ = reflect.DeepEqual
