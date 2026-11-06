// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"errors"
	"net/http"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type staticRotationVersionIntent struct {
	Fence         store.ApplicationSecretMutationFence
	Payload       projections.ApplicationSecretMutation
	Prepared      bool
	ResultVersion int
}

// Preparing the existing application-secret fence before a native inverse
// prevents another mutation from taking the publication slot during recovery.
// A committed receipt recovers the same result after a lost worker response.
func (a *API) prepareStaticRotationSecretVersion(ctx context.Context, cmd store.SecretStaticRotationCommand, step string, value []byte, expectedVersion int) (staticRotationVersionIntent, error) {
	idempotencyKey := cmd.ID + ":" + step
	principal := "static-rotation:" + cmd.ID
	request := struct {
		Command string `json:"command"`
		Step    string `json:"step"`
		Key     string `json:"key"`
	}{Command: cmd.ID, Step: step, Key: cmd.Key}
	keyDigest, binding, err := a.applicationSecretRequestBinding(cmd.TenantID, idempotencyKey, principal,
		"WORKER", "/api/v1/secrets/rotations/"+cmd.ID, "rotate", staticRotationSurface, cmd.Key, request)
	if err != nil {
		return staticRotationVersionIntent{}, err
	}
	eventID := applicationSecretMutationEventID(cmd.TenantID, cmd.TenantEpoch, cmd.Key, "rotate", keyDigest)
	if receipt, ok, err := a.applicationSecretMaterializedResult(ctx, cmd.TenantID, eventID, binding, cmd.Key, "rotate"); err != nil {
		return staticRotationVersionIntent{}, err
	} else if ok {
		return staticRotationVersionIntent{ResultVersion: receipt.ResultVersion}, nil
	}
	fence, payload, prepared, err := a.applicationSecretMutationFence(ctx, cmd.TenantID, cmd.Key, "rotate", eventID, binding)
	if err != nil {
		return staticRotationVersionIntent{}, err
	}
	if !prepared {
		current, err := a.secrets.be.Store.GetSecret(ctx, cmd.TenantID, cmd.Key)
		if err != nil {
			return staticRotationVersionIntent{}, err
		}
		if current.Version != expectedVersion {
			return staticRotationVersionIntent{}, errStatus(http.StatusConflict, staticRotationVersionMovedDetail)
		}
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
			"rotate", eventID, projections.EventApplicationSecretRotated, binding, payload)
		if err != nil {
			return staticRotationVersionIntent{}, err
		}
	}
	fence, payload, err = a.finalizeApplicationSecretMutationFence(ctx, cmd.TenantID, fence, payload)
	if err != nil {
		return staticRotationVersionIntent{}, err
	}
	return staticRotationVersionIntent{Fence: fence, Payload: payload, Prepared: prepared}, nil
}
func (a *API) commitStaticRotationSecretVersion(ctx context.Context, cmd store.SecretStaticRotationCommand, intent staticRotationVersionIntent) (int, error) {
	if intent.ResultVersion > 0 {
		return intent.ResultVersion, nil
	}
	_, canonical, err := a.appendAndProjectApplicationSecretMutation(ctx, cmd.TenantID, intent.Fence, intent.Payload, intent.Prepared)
	if err != nil {
		return 0, err
	}
	return canonical.ResultVersion, nil
}
