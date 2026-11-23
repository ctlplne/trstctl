// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/tenantseal"
)

// validateVerifiedRawHistory consumes only the finite HMAC-verified artifact
// view. It runs before opening target JetStream; a failed envelope, lifetime or
// nested sealed field must not leave a partially published raw source prefix.
func validateVerifiedRawHistory(ctx context.Context, source *backup.VerifiedHistoryReader,
	keys events.EventProtectionKeys, planner *eventprivacy.ErasurePlanner,
	access tenantseal.Access,
) error {
	if source == nil {
		return errors.New("server: raw-history preflight requires verified artifact")
	}
	cut, err := source.LastSequence(ctx)
	if err != nil {
		return err
	}
	protected := false
	if err := source.ReplayThrough(ctx, 1, cut, func(event events.Event) error {
		protected = protected || event.Protection != nil
		return nil
	}); err != nil {
		return err
	}
	validate := func(read context.Context, plan *eventprivacy.ErasurePlan) error {
		return source.ReplayThrough(read, 1, cut, func(event events.Event) error {
			defer secret.Wipe(event.Data)
			if err := events.ValidateBackupHistoryEvent(event); err != nil {
				return fmt.Errorf("server: raw-history envelope at sequence %d: %w", event.Sequence, err)
			}
			check := func(checkCtx context.Context, erased bool) error {
				if erased {
					return nil // The plan proved this exact lifetime's signed key destruction.
				}
				opened, err := events.AuthenticateBackupHistoryEvent(checkCtx, event, keys)
				if err != nil {
					return err
				}
				if event.Protection != nil {
					defer secret.Wipe(opened.Data)
				}
				if err := events.ValidateRegisteredEventPayload(opened); err != nil {
					return fmt.Errorf("server: raw-history schema at sequence %d: %w", event.Sequence, err)
				}
				return validateSealedIngressCandidate(checkCtx, access, opened)
			}
			if event.Protection != nil {
				if plan == nil {
					return errors.New("server: protected raw history requires signed erasure policy")
				}
				if err := plan.WithSource(read, event, check); err != nil {
					return fmt.Errorf("server: protected raw-history sequence %d: %w", event.Sequence, err)
				}
				return nil
			}
			if err := check(read, false); err != nil {
				return fmt.Errorf("server: raw-history sequence %d: %w", event.Sequence, err)
			}
			return nil
		})
	}
	if !protected {
		return validate(ctx, nil)
	}
	if planner == nil || keys == nil {
		return errors.New("server: protected raw history requires independent custody")
	}
	return planner.WithPlan(ctx, validate)
}
