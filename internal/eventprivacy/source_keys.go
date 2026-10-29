// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/eventprotect"
)

type VerifiedCustody interface {
	WithVerifiedKey(context.Context, eventprotect.KeyCreationEvidence, func(seal.KeyWrapper) error) error
	DestructionReceipt(context.Context, eventprotect.KeyRef) (string, bool, error)
}

// SourceKeys opens only the creation identity retained by the source. It never
// provisions a missing key and never uses a SQL policy row to select plaintext.
type SourceKeys struct {
	Policy  SourcePolicy
	Custody VerifiedCustody
}

func canonicalKeyRef(ref eventprotect.KeyRef) (eventprotect.KeyRef, error) {
	tenant, tenantErr := uuid.Parse(ref.TenantID)
	key, keyErr := uuid.Parse(ref.ID)
	if tenantErr != nil || keyErr != nil || tenant == uuid.Nil || key == uuid.Nil {
		return eventprotect.KeyRef{}, ErrSource
	}
	return eventprotect.KeyRef{TenantID: tenant.String(), ID: key.String()}, nil
}

// LifetimeForKey returns the historical lifetime that owns this key, including
// after another registration reuses the tenant UUID. Results remain private
// until the complete source read and generation verification succeed.
func (policy SourcePolicy) LifetimeForKey(ctx context.Context, ref eventprotect.KeyRef) (Lifetime, bool, error) {
	ref, err := canonicalKeyRef(ref)
	if err != nil || policy.Log == nil {
		return Lifetime{}, false, ErrSource
	}
	var result Lifetime
	var found bool
	err = policy.replayLifetimes(ctx, ref.TenantID, func(lifetime Lifetime) error {
		if lifetime.Activation == nil || lifetime.Activation.Body.Creation.Ref != ref {
			return nil
		}
		if found {
			return ErrSource
		}
		result, found = lifetime, true
		return nil
	})
	if err != nil {
		return Lifetime{}, false, err
	}
	return result, found, nil
}

func (reader SourceKeys) WithKey(ctx context.Context, ref eventprotect.KeyRef, visit func(seal.KeyWrapper) error) error {
	ref, err := canonicalKeyRef(ref)
	if err != nil || reader.Policy.Log == nil || reader.Custody == nil || visit == nil {
		return ErrSource
	}
	return reader.Policy.Log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		meta, found, err := reader.Policy.Log.TenantMetadataByID(readCtx, ref.TenantID, ref.ID)
		if err != nil {
			return err
		}
		if !found || meta.Type != EventActivated || meta.DeclaredKeyID != "" || meta.SchemaVersion != 1 {
			return ErrSource
		}
		lifetime, found, err := reader.Policy.LifetimeForKey(readCtx, ref)
		if err != nil {
			return err
		}
		if !found || lifetime.Activation == nil {
			return ErrSource
		}
		if lifetime.Completion != nil {
			receipt, erased, err := reader.Custody.DestructionReceipt(readCtx, ref)
			if err != nil {
				return err
			}
			if !erased || receipt != lifetime.Completion.JWS {
				return eventprotect.ErrKey
			}
		}
		return reader.Custody.WithVerifiedKey(readCtx, lifetime.Activation.Body.Creation, visit)
	})
}
