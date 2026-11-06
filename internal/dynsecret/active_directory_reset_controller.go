// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"errors"
	"trstctl.com/trstctl/internal/crypto/ldapbind"
)

// Native progress observation and a single selected-credential proof are kept
// separate from the administrative write. This is an interrupted-operation
// recovery protocol, not an atomic native compare-and-swap against other admins.
type adPreparedResetRuntime interface {
	Observe(context.Context) (adNativeResetIdentity, error)
	Prove(context.Context, adNativeResetIdentity, []byte) error
	Reset(context.Context, adNativeResetIdentity, []byte, bool) error
}

func driveADPreparedReset(ctx context.Context, p adStaticPreparation, old []byte, inverse bool, native adPreparedResetRuntime) error {
	if p.Version != 2 || native == nil {
		return errors.New("dynsecret AD: durable reset requires its complete versioned preparation")
	}
	for _, credential := range [][]byte{p.Password, p.ForwardIntermediate, p.InverseIntermediate} {
		if e := ldapbind.ValidateADGeneratedPassword(credential); e != nil {
			return e
		}
	}
	if inverse {
		if e := ldapbind.ValidateADRecoveryPassword(old); e != nil {
			return e
		}
	}
	target := uint8(2)
	if inverse {
		target = 4
	}
	// At most four distinct writes exist in this frozen operation. A retry reads
	// its current native version; it never generates another intermediate.
	for transition := 0; transition < 5; transition++ {
		if e := ctx.Err(); e != nil {
			return e
		}
		current, e := native.Observe(ctx)
		if e != nil {
			return e
		}
		position, e := p.resetPosition(current)
		if e != nil {
			return e
		}
		if !inverse && position > target {
			return errors.New("dynsecret AD: forward reset was superseded by inverse progress")
		}
		if inverse && position == 0 {
			return native.Prove(ctx, current, old)
		}
		if position > 0 {
			var selected []byte
			switch position {
			case 1:
				selected = p.ForwardIntermediate
			case 2:
				selected = p.Password
			case 3:
				selected = p.InverseIntermediate
			case 4:
				selected = old
			default:
				return errors.New("dynsecret AD: unknown native reset generation")
			}
			if e = native.Prove(ctx, current, selected); e != nil {
				return e
			}
			if position == target {
				return nil
			}
		}
		var next []byte
		switch position + 1 {
		case 1:
			next = p.ForwardIntermediate
		case 2:
			next = p.Password
		case 3:
			next = p.InverseIntermediate
		case 4:
			next = old
		default:
			return errors.New("dynsecret AD: reset generation exceeds the frozen operation")
		}
		if e = native.Reset(ctx, current, next, position+1 == 4); e != nil {
			return e
		}
		after, e := native.Observe(ctx)
		if e != nil {
			return e
		}
		observed, e := p.resetPosition(after)
		if e != nil {
			return e
		}
		if observed != position+1 {
			return errors.New("dynsecret AD: native write did not produce exactly its next frozen generation")
		}
	}
	return errors.New("dynsecret AD: native reset exceeded its fixed transition bound")
}
