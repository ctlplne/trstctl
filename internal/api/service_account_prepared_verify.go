// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"errors"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/store"
)

func (a *API) proveDependentDirectorySuccessor(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider) error {
	if _, err := boundStaticPreparation(provider, cmd); err != nil {
		return err
	}
	verifier, ok := provider.(dynsecret.PreparedStaticRotationVerifier)
	if !ok {
		return errors.New("api: coordinated native rotation requires a read-only prepared successor proof")
	}
	open := func(sealed []byte, part string) (*secret.Buffer, error) {
		raw, err := a.secrets.open(ctx, cmd.TenantID, sealed, staticRotationAAD(cmd.TenantID, cmd.ID, part))
		if err != nil {
			return nil, err
		}
		held, err := secret.NewFrom(raw)
		secret.Wipe(raw)
		if err != nil {
			return nil, err
		}
		if len(held.Bytes()) == 0 || len(held.Bytes()) > 64<<10 {
			held.Destroy()
			return nil, errors.New("api: final native proof material exceeds its bound")
		}
		return held, nil
	}
	prepared, err := open(cmd.SealedPreparation, "prepared")
	if err != nil {
		return err
	}
	defer prepared.Destroy()
	credential, err := open(cmd.SealedNew, "new")
	if err != nil {
		return err
	}
	defer credential.Destroy()
	return verifier.VerifyStaticPreparedCredential(ctx, staticPreparedRequest(cmd), prepared.Bytes(), credential.Bytes())
}
