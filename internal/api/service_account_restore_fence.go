// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var errStaticRotationVersionMoved = errors.New(staticRotationVersionMovedDetail)

type staticRotationVersionIntent struct {
	Fence         store.ApplicationSecretMutationFence
	Payload       projections.ApplicationSecretMutation
	Prepared      bool
	Rollback      bool
	ResultVersion int
}

// Preparing the existing application-secret fence before a native inverse
// prevents another mutation from taking the publication slot during recovery.
// A committed receipt recovers the same result after a lost worker response.
func (a *API) prepareStaticRotationSecretVersion(ctx context.Context, cmd store.SecretStaticRotationCommand, step string, value []byte, expectedVersion int) (staticRotationVersionIntent, error) {
	var intent staticRotationVersionIntent
	err := a.store.WithStaticRotationPublicationLock(ctx, cmd.TenantID, cmd.ID, func(ctx context.Context) error {
		if err := a.requireStaticRotationPublicationPhase(ctx, cmd); err != nil {
			return err
		}
		var err error
		intent, err = a.prepareLockedStaticRotationSecretVersion(ctx, cmd, step, value, expectedVersion)
		return err
	})
	return intent, err
}

func (a *API) prepareLockedStaticRotationSecretVersion(ctx context.Context, cmd store.SecretStaticRotationCommand, step string, value []byte, expectedVersion int) (staticRotationVersionIntent, error) {
	idempotencyKey := cmd.ID + ":" + step
	eventID, keyDigest, binding, err := a.staticRotationPublicationIdentity(cmd, step)
	if err != nil {
		return staticRotationVersionIntent{}, err
	}
	if receipt, ok, err := a.applicationSecretMaterializedResult(ctx, cmd.TenantID, eventID, binding, cmd.Key, "rotate"); err != nil {
		return staticRotationVersionIntent{}, err
	} else if ok {
		return staticRotationVersionIntent{ResultVersion: receipt.ResultVersion}, nil
	}
	fence, payload, prepared, err := a.applicationSecretMutationFence(ctx, cmd.TenantID, cmd.Key, "rotate", eventID, binding)
	if err != nil {
		return staticRotationVersionIntent{}, err
	}
	current, err := a.secrets.be.Store.GetSecret(ctx, cmd.TenantID, cmd.Key)
	if err != nil {
		return staticRotationVersionIntent{}, err
	}
	if current.Version != expectedVersion {
		if receipt, found, err := a.applicationSecretMaterializedResult(ctx, cmd.TenantID, eventID, binding, cmd.Key, "rotate"); err != nil || found {
			return staticRotationVersionIntent{ResultVersion: receipt.ResultVersion}, err
		}
		return staticRotationVersionIntent{}, errWithStatus(http.StatusConflict, errStaticRotationVersionMoved)
	}
	if step == "cutover" {
		_, bound, err := a.staticRotationQueueReferenceEvidence(ctx, cmd)
		if err != nil {
			return staticRotationVersionIntent{}, err
		}
		if bound != nil && !nativeStaticRotationMatchesSecret(bound, current) {
			return staticRotationVersionIntent{}, errWithStatus(http.StatusConflict, errStaticRotationVersionMoved)
		}
	} else if step == "rollback" && cmd.ResultVersion > 0 {
		receipt, found, err := a.staticRotationPublicationReceipt(ctx, cmd, "cutover")
		if err != nil {
			return staticRotationVersionIntent{}, err
		}
		if !found || !staticRotationReceiptMatchesSecret(receipt, current) {
			return staticRotationVersionIntent{}, errWithStatus(http.StatusConflict, errStaticRotationVersionMoved)
		}
	}
	if !prepared {
		commandKeyDigest, evidence, err := a.applicationSecretCommandEvidence(cmd.TenantID, idempotencyKey, canonicalApplicationSecretCommand{
			Domain: "trstctl.api.application-secret-command.v2", TenantEpoch: cmd.TenantEpoch,
			Action: "rotate", Name: cmd.Key, Surface: staticRotationSurface, Provider: cmd.Provider,
			OldRef: cmd.OldRef, ExpectedVersion: expectedVersion, ResultVersion: expectedVersion + 1, Value: value,
		})
		if err != nil {
			return staticRotationVersionIntent{}, err
		}
		if commandKeyDigest != keyDigest {
			return staticRotationVersionIntent{}, errors.New("api: static rotation idempotency digest changed")
		}
		sealed, err := a.secrets.seal(ctx, cmd.TenantID, value, sealAAD(cmd.TenantID, cmd.Key))
		if err != nil {
			return staticRotationVersionIntent{}, err
		}
		payload = projections.ApplicationSecretMutation{
			TenantEpoch: cmd.TenantEpoch, Action: "rotate", Name: cmd.Key,
			ExpectedVersion: expectedVersion, ResultVersion: expectedVersion + 1, Sealed: sealed,
			IdempotencyKeyDigest: keyDigest, RequestBinding: binding,
			CommandEvidence: evidence, Surface: staticRotationSurface,
		}
		fence, payload, err = a.claimApplicationSecretMutationFence(ctx, cmd.TenantID, cmd.Key,
			"rotate", eventID, projections.EventApplicationSecretRotated, binding, payload,
			store.ApplicationSecretLiveVersion{Version: current.Version, CreatedAt: current.CreatedAt, UpdatedAt: current.UpdatedAt})
		if errors.Is(err, store.ErrApplicationSecretLiveVersionMoved) {
			return staticRotationVersionIntent{}, errWithStatus(http.StatusConflict, errStaticRotationVersionMoved)
		}
		if err != nil {
			return staticRotationVersionIntent{}, err
		}
	}
	fence, payload, err = a.finalizeApplicationSecretMutationFence(ctx, cmd.TenantID, fence, payload)
	if err != nil {
		return staticRotationVersionIntent{}, err
	}
	intent := staticRotationVersionIntent{Fence: fence, Payload: payload, Prepared: prepared, Rollback: step == "rollback"}
	// A source event retained after SQL failure proves the inverse already ran.
	// An authorized reservation also survives interrupted publication before an
	// event can be read. Continue it before considering another native effect.
	event, found, err := a.log.EventByID(ctx, fence.EventID)
	if err != nil {
		return staticRotationVersionIntent{}, err
	}
	if found || (intent.Rollback && fence.RollbackPublicationAuthorized) {
		if found && (event.TenantID != cmd.TenantID || event.Type != fence.EventType) {
			return staticRotationVersionIntent{}, errors.New("api: retained rotation publication differs from its tenant/fence")
		}
		version, err := a.commitLockedStaticRotationSecretVersion(ctx, cmd, intent)
		if err != nil {
			return staticRotationVersionIntent{}, err
		}
		return staticRotationVersionIntent{ResultVersion: version}, nil
	}
	return intent, nil
}
func (a *API) commitStaticRotationSecretVersion(ctx context.Context, cmd store.SecretStaticRotationCommand, intent staticRotationVersionIntent) (int, error) {
	if intent.ResultVersion > 0 {
		return intent.ResultVersion, nil
	}
	var version int
	err := a.store.WithStaticRotationPublicationLock(ctx, cmd.TenantID, cmd.ID, func(ctx context.Context) error {
		if err := a.requireStaticRotationPublicationPhase(ctx, cmd); err != nil {
			return err
		}
		var err error
		version, err = a.commitLockedStaticRotationSecretVersion(ctx, cmd, intent)
		return err
	})
	return version, err
}

func (a *API) requireStaticRotationPublicationPhase(ctx context.Context, cmd store.SecretStaticRotationCommand) error {
	if found, err := a.recoverStaticRotationAdvance(ctx, cmd, store.SecretStaticRotationRollbackFailed); err != nil {
		return orchestrator.DeferDelivery(err)
	} else if found {
		return orchestrator.DeferDelivery(errors.New("static rotation rollback failure requires recovery"))
	}
	current, err := a.store.GetSecretStaticRotationCommand(ctx, cmd.TenantID, cmd.ID)
	if err != nil {
		return orchestrator.DeferDelivery(err)
	}
	if current.Phase != cmd.Phase || current.Terminal() {
		return orchestrator.DeferDelivery(errors.New("static rotation advanced before vault publication"))
	}
	return nil
}

func (a *API) recoverFailedStaticRotationRollback(ctx context.Context, cmd store.SecretStaticRotationCommand) (bool, error) {
	switch cmd.Phase {
	case store.SecretStaticRotationPrepared, store.SecretStaticRotationStaged, store.SecretStaticRotationCutover:
		return a.recoverStaticRotationAdvance(ctx, cmd, store.SecretStaticRotationRollbackFailed)
	default:
		return false, nil
	}
}

func (a *API) commitLockedStaticRotationSecretVersion(ctx context.Context, cmd store.SecretStaticRotationCommand, intent staticRotationVersionIntent) (int, error) {
	if intent.Rollback && !intent.Fence.RollbackPublicationAuthorized {
		if err := a.store.AuthorizeStaticRollbackPublication(ctx, cmd, intent.Fence.EventID, intent.Fence.RequestBinding); err != nil {
			return 0, err
		}
	}
	_, canonical, err := a.appendAndProjectApplicationSecretMutation(ctx, cmd.TenantID, intent.Fence, intent.Payload, intent.Prepared)
	return canonical.ResultVersion, err
}

// Settle a failed native inverse without publishing a rollback. Publication
// and abandonment use the same command lock, so the draft cannot be released
// in the gap after another worker appends it.
func (a *API) settleFailedStaticRotationRollback(ctx context.Context, cmd store.SecretStaticRotationCommand) error {
	return a.store.WithStaticRotationPublicationLock(ctx, cmd.TenantID, cmd.ID, func(ctx context.Context) error {
		eventID, _, binding, err := a.staticRotationPublicationIdentity(cmd, "rollback")
		if err != nil {
			return err
		}
		fence, _, owned, err := a.applicationSecretMutationFence(ctx, cmd.TenantID, cmd.Key, "rotate", eventID, binding)
		if err != nil {
			return err
		}
		_, committed, err := a.applicationSecretMaterializedResult(ctx, cmd.TenantID, eventID, binding, cmd.Key, "rotate")
		if err != nil {
			return err
		}
		_, appended, err := a.log.EventByID(ctx, eventID)
		if err != nil {
			return err
		}
		if committed || appended || (owned && fence.RollbackPublicationAuthorized) {
			if cmd.Phase == store.SecretStaticRotationRollbackFailed {
				return nil // keep the publication's exact reservation for replay
			}
			return orchestrator.DeferDelivery(errors.New("static rotation rollback publication requires recovery"))
		}
		current, err := a.store.GetSecretStaticRotationCommand(ctx, cmd.TenantID, cmd.ID)
		if err != nil {
			return err
		}
		if current.Phase != store.SecretStaticRotationRollbackFailed {
			if current.Phase != cmd.Phase || current.Terminal() {
				return store.ErrIdempotencyConflict
			}
			if err := a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{
				Phase: store.SecretStaticRotationRollbackFailed, Error: staticRotationRestoreFailedDetail,
			}); err != nil {
				return err
			}
		}
		return a.store.ReleaseFailedStaticRollbackFence(ctx, cmd, eventID, binding)
	})
}

func (a *API) staticRotationPublicationReceipt(ctx context.Context, cmd store.SecretStaticRotationCommand, step string) (store.ApplicationSecretMutationReceipt, bool, error) {
	eventID, _, binding, err := a.staticRotationPublicationIdentity(cmd, step)
	if err != nil {
		return store.ApplicationSecretMutationReceipt{}, false, err
	}
	return a.applicationSecretMaterializedResult(ctx, cmd.TenantID, eventID, binding, cmd.Key, "rotate")
}

type staticRotationPublication struct {
	receipt            store.ApplicationSecretMutationReceipt
	committed, pending bool
}

// Read the exact fence before its receipt. Projection records the receipt and
// removes the fence in one transaction, so either read can establish authority
// while a concurrent reconciliation moves the publication between them.
func (a *API) staticRotationPublicationState(ctx context.Context, cmd store.SecretStaticRotationCommand, step string) (staticRotationPublication, error) {
	eventID, _, binding, err := a.staticRotationPublicationIdentity(cmd, step)
	if err != nil {
		return staticRotationPublication{}, err
	}
	_, _, pending, err := a.applicationSecretMutationFence(ctx, cmd.TenantID, cmd.Key, "rotate", eventID, binding)
	if err != nil {
		return staticRotationPublication{}, err
	}
	receipt, committed, err := a.applicationSecretMaterializedResult(ctx, cmd.TenantID, eventID, binding, cmd.Key, "rotate")
	if err != nil || committed || pending {
		return staticRotationPublication{receipt: receipt, committed: committed, pending: pending}, err
	}
	event, found, err := a.log.EventByID(ctx, eventID)
	if err == nil && found && (event.TenantID != cmd.TenantID || event.Type != projections.EventApplicationSecretRotated || event.SensitiveErased) {
		return staticRotationPublication{}, store.ErrIdempotencyConflict
	}
	return staticRotationPublication{pending: found}, err
}

func (a *API) staticRotationPublicationIdentity(cmd store.SecretStaticRotationCommand, step string) (eventID, keyDigest, binding string, err error) {
	request := struct {
		Command string `json:"command"`
		Step    string `json:"step"`
		Key     string `json:"key"`
	}{cmd.ID, step, cmd.Key}
	keyDigest, binding, err = a.applicationSecretRequestBinding(cmd.TenantID, cmd.ID+":"+step, "static-rotation:"+cmd.ID, "WORKER", "/api/v1/secrets/rotations/"+cmd.ID, "rotate", staticRotationSurface, cmd.Key, request)
	if err != nil {
		return "", "", "", err
	}
	return applicationSecretMutationEventID(cmd.TenantID, cmd.TenantEpoch, cmd.Key, "rotate", keyDigest), keyDigest, binding, nil
}
