// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

type CompletionFenceCustody interface {
	WithCustodyFence(context.Context, eventprotect.KeyRef, func(context.Context) error) error
	DestructionReceipt(context.Context, eventprotect.KeyRef) (string, bool, error)
}

type CompletionVerifier struct {
	Policy  SourcePolicy
	Custody CompletionFenceCustody
}

// WithVerifiedCompletion holds independent custody through the existing SQL
// projection. The signed source record and CURRENT independently verified
// absence must both agree; a syntax-valid JWS or missing file alone is refused.
func (verifier CompletionVerifier) WithVerifiedCompletion(ctx context.Context, event events.Event, visit func(context.Context, eventprotect.DestructionRequest) error) error {
	body, err := ParseDestroyed(event)
	if err != nil || verifier.Policy.Log == nil || verifier.Custody == nil || visit == nil {
		return ErrSource
	}
	claims, err := verifier.Policy.verifyDestructionReceipt(body.JWS)
	if err != nil {
		return err
	}
	tenant, tenantErr := uuid.Parse(event.TenantID)
	if tenantErr != nil || tenant == uuid.Nil || tenant.String() != claims.Request.Ref.TenantID {
		return ErrSource
	}
	return verifier.Policy.Log.WithHistoryRead(ctx, func(read context.Context) error {
		life, found, err := verifier.Policy.LifetimeForKey(read, claims.Request.Ref)
		if err != nil {
			return err
		}
		if !found || !matchesLifetimeDestruction(life, claims.Request) || life.Completion == nil || life.Completion.Meta.ID != event.ID || life.Completion.Meta.Sequence != event.Sequence || !life.Completion.Meta.Time.Equal(event.Time) || life.Completion.JWS != body.JWS {
			return ErrSource
		}
		return verifier.Custody.WithCustodyFence(read, claims.Request.Ref, func(fenced context.Context) error {
			receipt, erased, err := verifier.Custody.DestructionReceipt(fenced, claims.Request.Ref)
			if err != nil {
				return err
			}
			if !erased || receipt != body.JWS {
				return eventprotect.ErrKey
			}
			return visit(fenced, claims.Request)
		})
	})
}
