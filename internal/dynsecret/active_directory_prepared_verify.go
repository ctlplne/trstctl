// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"errors"
	"trstctl.com/trstctl/internal/crypto"
)

// VerifyStaticPreparedCredential independently re-observes the pinned native
// object and exact final generation. It has no reset path, including on drift.
func (b *LDAPBackend) VerifyStaticPreparedCredential(ctx context.Context, req GenerateRequest, raw, credential []byte, binding string) error {
	p, _, err := b.boundADPreparation(ctx, req, raw, binding)
	if err != nil {
		return err
	}
	defer p.destroy()
	return verifyADPreparedSuccessor(ctx, p, credential, newADPreparedResetNative(b, p))
}
func verifyADPreparedSuccessor(ctx context.Context, p adStaticPreparation, credential []byte, native adPreparedResetRuntime) error {
	if p.Version != 2 || native == nil {
		return errors.New("dynsecret AD: final native proof requires its complete durable preparation")
	}
	held, err := decodeADPredecessorPassword(credential, p.DN)
	if err != nil {
		return err
	}
	defer held.Destroy()
	if !crypto.ConstantTimeEqual(held.Bytes(), p.Password) {
		return errors.New("dynsecret AD: sealed successor differs from prepared generation")
	}
	current, err := native.Observe(ctx)
	if err != nil {
		return err
	}
	position, err := p.resetPosition(current)
	if err != nil {
		return err
	}
	if position != 2 {
		return errors.New("dynsecret AD: final native generation is not the prepared successor")
	}
	return native.Prove(ctx, current, p.Password)
}
