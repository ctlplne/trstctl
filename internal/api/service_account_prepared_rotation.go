// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func staticPreparedRequest(cmd store.SecretStaticRotationCommand) dynsecret.GenerateRequest {
	return dynsecret.GenerateRequest{Role: cmd.Key, LeaseID: cmd.ID, Static: true, Predecessor: cmd.OldRef}
}
func boundStaticPreparation(provider dynsecret.Provider, cmd store.SecretStaticRotationCommand) (dynsecret.PreparedStaticRotationProvider, error) {
	prepared, ok := provider.(dynsecret.PreparedStaticRotationProvider)
	if !ok || cmd.ProviderBinding == "" || prepared.StaticRotationBinding(cmd.Key) != cmd.ProviderBinding {
		return nil, errors.New("api: frozen native rotation provider configuration changed")
	}
	return prepared, nil
}
func (a *API) recoverStaticRotationAdvance(ctx context.Context, cmd store.SecretStaticRotationCommand, phase string) (bool, error) {
	event, found, err := a.log.EventByID(ctx, staticRotationEventID(cmd, phase))
	if err != nil || !found {
		return false, err
	}
	var value projections.SecretStaticRotationAdvanced
	if event.TenantID != cmd.TenantID || event.Type != projections.EventSecretStaticRotationAdvanced || json.Unmarshal(event.Data, &value) != nil || value.ID != cmd.ID || value.TenantEpoch != cmd.TenantEpoch || value.Phase != phase {
		return false, errors.New("api: retained native rotation phase has a different binding")
	}
	if err := projections.New(a.store).Apply(ctx, event); err != nil {
		return false, err
	}
	return true, nil
}
func (a *API) prepareStaticNativeRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider) error {
	if found, err := a.recoverStaticRotationAdvance(ctx, cmd, store.SecretStaticRotationPrepared); err != nil || found {
		return err
	}
	preparer, err := boundStaticPreparation(provider, cmd)
	if err != nil {
		return err
	}
	current, err := a.secrets.be.Store.GetSecret(ctx, cmd.TenantID, cmd.Key)
	if err != nil {
		return err
	}
	if current.Version != cmd.ExpectedVersion {
		return errStatus(http.StatusConflict, staticRotationVersionMovedDetail)
	}
	old, err := a.secrets.open(ctx, cmd.TenantID, current.Sealed, sealAAD(cmd.TenantID, cmd.Key))
	if err != nil {
		return err
	}
	oldHeld, err := secret.NewFrom(old)
	secret.Wipe(old)
	if err != nil {
		return err
	}
	defer oldHeld.Destroy()
	if cmd.DependentChangeID != "" {
		parent, err := a.dependentRotationParent(ctx, cmd)
		if err != nil {
			return err
		}
		if parent.Intent.Mode == servicedependents.Reconcile {
			validator, ok := provider.(dynsecret.StaticRecoveryCredentialValidator)
			if !ok || validator.ValidateStaticRecoveryCredential(staticPreparedRequest(cmd), oldHeld.Bytes()) != nil {
				return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationFailed, Error: "retained vault generation cannot recover this exact native account; no directory reset was performed"})
			}
		}
	}
	prepared, err := preparer.PrepareStaticCredential(ctx, staticPreparedRequest(cmd))
	if err != nil {
		secret.Wipe(prepared)
		return err
	}
	preparedHeld, err := secret.NewFrom(prepared)
	secret.Wipe(prepared)
	if err != nil {
		return err
	}
	defer preparedHeld.Destroy()
	if len(preparedHeld.Bytes()) == 0 || len(preparedHeld.Bytes()) > 64<<10 {
		return errors.New("api: native rotation returned an invalid preparation")
	}
	sealed, err := a.secrets.seal(ctx, cmd.TenantID, preparedHeld.Bytes(), staticRotationAAD(cmd.TenantID, cmd.ID, "prepared"))
	if err != nil {
		return err
	}
	sealedOld, err := a.secrets.seal(ctx, cmd.TenantID, oldHeld.Bytes(), staticRotationAAD(cmd.TenantID, cmd.ID, "old"))
	if err != nil {
		return err
	}
	advance := projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationPrepared, SealedPreparation: sealed, SealedOld: sealedOld}
	if host, ok := provider.(dynsecret.PreparedHostStaticRotationProvider); ok {
		intent, e := host.PreparedHostRotationIntent(staticPreparedRequest(cmd), preparedHeld.Bytes(), oldHeld.Bytes())
		if e != nil {
			return e
		}
		advance.WindowsLocalIntent = &intent
	}
	preparedHeld.Destroy()
	oldHeld.Destroy()
	return a.advanceStaticRotation(ctx, cmd, advance)
}
func (a *API) stagePreparedStaticRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider) error {
	if found, err := a.recoverStaticRotationAdvance(ctx, cmd, store.SecretStaticRotationStaged); err != nil || found {
		return err
	}
	preparer, err := boundStaticPreparation(provider, cmd)
	if err != nil {
		return err
	}
	raw, err := a.secrets.open(ctx, cmd.TenantID, cmd.SealedPreparation, staticRotationAAD(cmd.TenantID, cmd.ID, "prepared"))
	if err != nil {
		return err
	}
	held, err := secret.NewFrom(raw)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	defer held.Destroy()
	credential, err := preparer.GenerateStaticPrepared(ctx, staticPreparedRequest(cmd), held.Bytes())
	if err != nil {
		secret.Wipe(credential.Secret)
		return err
	}
	newHeld, err := secret.NewFrom(credential.Secret)
	secret.Wipe(credential.Secret)
	if err != nil {
		return err
	}
	defer newHeld.Destroy()
	if credential.BackendRef == "" || len(newHeld.Bytes()) == 0 {
		return errors.New("api: prepared native apply returned no credential")
	}
	sealed, err := a.secrets.seal(ctx, cmd.TenantID, newHeld.Bytes(), staticRotationAAD(cmd.TenantID, cmd.ID, "new"))
	if err != nil {
		return err
	}
	newHeld.Destroy()
	held.Destroy()
	return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationStaged, ProviderType: credential.Metadata["provider_type"], NewRef: credential.BackendRef, SealedNew: sealed})
}
func (a *API) cutoverPreparedStaticRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider) error {
	if found, err := a.recoverStaticRotationAdvance(ctx, cmd, store.SecretStaticRotationCutover); err != nil || found {
		return err
	}
	value, err := a.secrets.open(ctx, cmd.TenantID, cmd.SealedNew, staticRotationAAD(cmd.TenantID, cmd.ID, "new"))
	if err != nil {
		return err
	}
	valueHeld, err := secret.NewFrom(value)
	secret.Wipe(value)
	if err != nil {
		return err
	}
	defer valueHeld.Destroy()
	if err = a.verifyPreparedHostGeneration(ctx, cmd, provider, valueHeld.Bytes()); err != nil {
		return err
	}
	version, err := a.writeStaticRotationSecretVersion(ctx, cmd, "cutover", valueHeld.Bytes(), cmd.ExpectedVersion)
	if err != nil {
		return err
	}
	valueHeld.Destroy()
	return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationCutover, ResultVersion: version})
}
func (a *API) restorePreparedNativeRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider, old []byte) error {
	preparer, err := boundStaticPreparation(provider, cmd)
	if err != nil {
		return err
	}
	raw, err := a.secrets.open(ctx, cmd.TenantID, cmd.SealedPreparation, staticRotationAAD(cmd.TenantID, cmd.ID, "prepared"))
	if err != nil {
		return err
	}
	held, err := secret.NewFrom(raw)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	defer held.Destroy()
	return preparer.RestorePreparedStaticCredential(ctx, staticPreparedRequest(cmd), held.Bytes(), old)
}

// Check retained native evidence before any application-secret publication.
// A later phase event cannot undo a vault write made before discovering that a
// cached native completion has lost or substituted its immutable source.
func (a *API) verifyPreparedHostGeneration(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider, value []byte) error {
	if _, host := provider.(dynsecret.PreparedHostStaticRotationProvider); !host {
		return nil
	}
	if cmd.NewRef != cmd.ID {
		return errors.New("native local generation reference differs from its command")
	}
	if _, e := boundStaticPreparation(provider, cmd); e != nil {
		return e
	}
	verifier, ok := provider.(dynsecret.PreparedStaticRotationVerifier)
	if !ok {
		return errors.New("native local generation verifier unavailable")
	}
	raw, e := a.secrets.open(ctx, cmd.TenantID, cmd.SealedPreparation, staticRotationAAD(cmd.TenantID, cmd.ID, "prepared"))
	if e != nil {
		return e
	}
	held, e := secret.NewFrom(raw)
	secret.Wipe(raw)
	if e != nil {
		return e
	}
	defer held.Destroy()
	return verifier.VerifyStaticPreparedCredential(ctx, staticPreparedRequest(cmd), held.Bytes(), value)
}
