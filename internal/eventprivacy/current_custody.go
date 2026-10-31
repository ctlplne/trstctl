// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

// VerifyCurrentCustody checks every retained public activation against its exact
// source lifetime and current independent material or signed verified removal.
// No SQL projection, cached key handle, or caller-erased flag grants health.
// The caller bounds time and concurrency; this scan keeps no key buffers or
// per-event results and visits only the finite public activation type cut.
func (reader SourceKeys) VerifyCurrentCustody(ctx context.Context) error {
	if reader.Policy.Log == nil {
		return ErrSource
	}
	return reader.Policy.Log.WithHistoryRead(ctx, func(read context.Context) error {
		head, err := reader.Policy.Log.LastSequence(read)
		if err != nil {
			return err
		}
		if err := reader.Policy.Log.ReplayTypesThrough(read, 1, head, []string{EventActivated}, func(event events.Event) error {
			activation, err := ParseActivated(event)
			if err != nil {
				return err
			}
			err = reader.WithKey(read, activation.Creation.Ref, func(seal.KeyWrapper) error { return nil })
			// SourceKeys binds the exact creation and FileAuthority verifies the signed
			// journal plus actual absence. Missing material alone returns ErrKey.
			if errors.Is(err, eventprotect.ErrDestroyed) {
				return nil
			}
			return err
		}); err != nil {
			return err
		}
		if reader.Custody == nil {
			return nil
		}
		tenants := map[string]bool{}
		if err := reader.Policy.Log.ReplayTypesThrough(read, 1, head, []string{eventRegistered}, func(event events.Event) error { tenants[event.TenantID] = true; return nil }); err != nil {
			return err
		}
		for tenant := range tenants {
			if err := reader.Policy.replayLifetimesThrough(read, tenant, head, func(life Lifetime) error {
				if life.Activation != nil {
					return nil
				}
				return reader.Policy.withRegistrationFloor(read, life, reader.Custody, func(_ context.Context, floor registrationFloor) error {
					if floor.found && !floor.erased && life.Request == nil && life.Offboard == nil {
						return ErrSource
					}
					return nil
				})
			}); err != nil {
				return err
			}
		}
		return nil
	})
}
