// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"errors"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// OpenWindowsLocalRotationCredentials is the one-purpose broker behind the
// certificate/host/current-claim/single-use redemption gate. It opens only this
// command's two sealed generations and cannot resolve arbitrary secret refs.
func (a *API) OpenWindowsLocalRotationCredentials(ctx context.Context, tenantID string, i hostaccounts.RotationIntent, jobID int64, attempt int) ([]byte, []byte, error) {
	if a.secrets == nil || i.TenantID != tenantID || i.Validate() != nil {
		return nil, nil, errors.New("native credential authority is invalid")
	}
	v, cmd, e := projections.CanonicalWindowsLocalRotation(ctx, a.store, a.log, tenantID, i.RotationID)
	if e != nil {
		return nil, nil, e
	}
	if v.Intent != i || cmd.Phase != store.SecretStaticRotationPrepared || v.Observation != nil && (v.Observation.Report.Status == "succeeded" || v.Observation.Report.Status == "not_applied") {
		return nil, nil, errors.New("native credential generation is no longer pending")
	}
	if v.OutboxID == nil || *v.OutboxID != jobID || attempt <= 0 {
		return nil, nil, errors.New("native credential delivery differs")
	}
	if _, found, err := a.log.EventByID(ctx, hostaccounts.RotationObservationSourceID(tenantID, jobID, attempt)); err != nil {
		return nil, nil, err
	} else if found {
		return nil, nil, errors.New("native attempt already has retained report evidence; project it before further work")
	}
	provider, _, e := a.staticRotationProvider(tenantID, cmd.Provider, cmd.Key)
	if e != nil {
		return nil, nil, e
	}
	if _, ok := provider.(dynsecret.PreparedHostStaticRotationProvider); !ok {
		return nil, nil, errors.New("native credential provider changed")
	}
	if _, e = boundStaticPreparation(provider, cmd); e != nil {
		return nil, nil, e
	}
	raw, e := a.secrets.open(ctx, tenantID, cmd.SealedPreparation, staticRotationAAD(tenantID, cmd.ID, "prepared"))
	if e != nil {
		return nil, nil, e
	}
	held, e := secret.NewFrom(raw)
	secret.Wipe(raw)
	if e != nil {
		return nil, nil, e
	}
	defer held.Destroy()
	preparation, e := hostaccounts.DecodeRotationPreparation(held.Bytes())
	if e != nil {
		return nil, nil, e
	}
	defer secret.Wipe(preparation.Credential.Password)
	if preparation.Intent != i || preparation.ProviderBinding != cmd.ProviderBinding || preparation.Role != cmd.Key {
		return nil, nil, errors.New("native sealed generation differs")
	}
	raw, e = a.secrets.open(ctx, tenantID, cmd.SealedOld, staticRotationAAD(tenantID, cmd.ID, "old"))
	if e != nil {
		return nil, nil, e
	}
	oldHeld, e := secret.NewFrom(raw)
	secret.Wipe(raw)
	if e != nil {
		return nil, nil, e
	}
	defer oldHeld.Destroy()
	old, e := hostaccounts.DecodeLocalCredential(oldHeld.Bytes(), i)
	if e != nil {
		return nil, nil, e
	}
	// Ownership transfers to the resolver, which immediately locks these buffers.
	return old.Password, append([]byte(nil), preparation.Credential.Password...), nil
}
