// SPDX-License-Identifier: BUSL-1.1
package eventprivacy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"strconv"
	"strings"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
)

type PostgresArtifactCustody interface {
	VerifiedCustody
	ErasurePlanCustody
	registrationCustody
}

// SourcePostgresProtection belongs to ONE authenticated/attested paired cut.
// It is read-only key access; it grants no provisioning, signing or destruction.
type SourcePostgresProtection struct {
	Policy  SourcePolicy
	Custody PostgresArtifactCustody
	Cut     uint64
}

func postgresArtifactPolicyDigest() string {
	return crypto.SHA256Hex([]byte("trstctl.postgres-state-sensitive-row.v2"))
}
func (p SourcePostgresProtection) validateBinding(binding eventprotect.Context) error {
	parts := strings.Split(binding.ID, ":")
	if binding.Scope != eventprotect.ScopePostgresRow || binding.SchemaVersion != 2 || binding.Time.IsZero() || len(parts) != 4 {
		return ErrSource
	}
	artifact, err := uuid.Parse(parts[0])
	if err != nil || artifact.Version() != 4 || artifact.String() != parts[0] {
		return ErrSource
	}
	cut, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || cut != p.Cut {
		return ErrSource
	}
	ordinal, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || ordinal == 0 || len(parts[3]) != 64 {
		return ErrSource
	}
	digest, err := hex.DecodeString(parts[3])
	if err != nil || len(digest) != 32 || strings.ToLower(parts[3]) != parts[3] {
		return ErrSource
	}
	tenant, err := uuid.Parse(binding.TenantID)
	if err != nil || tenant == uuid.Nil || tenant.String() != binding.TenantID {
		return ErrSource
	}
	return nil
}
func (p SourcePostgresProtection) withCutLifetime(ctx context.Context, tenant string, visit func(context.Context, Lifetime) error) error {
	if p.Policy.Log == nil || visit == nil || p.Cut == 0 {
		return ErrSource
	}
	identity, err := uuid.Parse(tenant)
	if err != nil || identity == uuid.Nil || identity.String() != tenant {
		return ErrSource
	}
	return p.Policy.Log.WithHistoryRead(ctx, func(read context.Context) error {
		head, err := p.Policy.Log.LastSequence(read)
		if err != nil {
			return err
		}
		if p.Cut > head {
			return ErrSource
		}
		var life Lifetime
		if err := p.Policy.replayLifetimesThrough(read, tenant, p.Cut, func(next Lifetime) error { life = next; return nil }); err != nil {
			return err
		}
		return visit(read, life)
	})
}
func (p SourcePostgresProtection) withLifetimeKey(ctx context.Context, life Lifetime, visit func(seal.KeyWrapper) error) (bool, error) {
	if life.Activation == nil || p.Custody == nil {
		return false, eventprotect.ErrKey
	}
	ref := life.Activation.Body.Creation.Ref
	erased := false
	err := p.Custody.WithCustodyFence(ctx, ref, func(fenced context.Context) error {
		reader := SourceKeys{Policy: p.Policy, Custody: p.Custody}
		err := reader.WithKey(fenced, ref, visit)
		if !errors.Is(err, eventprotect.ErrDestroyed) {
			return err
		}
		receipt, removed, err := p.Custody.DestructionReceipt(fenced, ref)
		if err != nil {
			return err
		}
		if !removed {
			return eventprotect.ErrKey
		}
		claims, err := p.Policy.verifyDestructionReceipt(receipt)
		if err != nil {
			return err
		}
		matches, err := p.Policy.receiptMatchesCurrentLifetime(fenced, life, claims, p.Cut, p.Custody, receipt)
		if err != nil {
			return err
		}
		if !matches || (life.Completion != nil && life.Completion.JWS != receipt) {
			return ErrSource
		}
		erased = true
		return nil
	})
	return erased, err
}
func (p SourcePostgresProtection) ProtectPostgresRow(ctx context.Context, binding eventprotect.Context, row json.RawMessage) (eventprotect.Envelope, bool, error) {
	if err := p.validateBinding(binding); err != nil {
		return eventprotect.Envelope{}, false, err
	}
	var envelope eventprotect.Envelope
	protected := false
	err := p.withCutLifetime(ctx, binding.TenantID, func(read context.Context, life Lifetime) error {
		if life.Activation == nil {
			return p.Policy.withRegistrationFloor(read, life, p.Custody, func(_ context.Context, floor registrationFloor) error {
				if floor.erased {
					return ErrOffboarded
				}
				if floor.found || life.Request != nil {
					return ErrPreparing
				}
				return nil
			})
		}
		erased, err := p.withLifetimeKey(read, life, func(key seal.KeyWrapper) error {
			var err error
			envelope, err = eventprotect.Protect(key, binding, life.Activation.Body.Creation.Ref.ID, postgresArtifactPolicyDigest(), eventprotect.Payload{Data: row})
			return err
		})
		if err != nil {
			return err
		}
		if erased {
			return eventprotect.ErrDestroyed
		}
		protected = true
		return nil
	})
	return envelope, protected, err
}
func (p SourcePostgresProtection) OpenPostgresRow(ctx context.Context, binding eventprotect.Context, envelope eventprotect.Envelope) (json.RawMessage, bool, error) {
	if err := p.validateBinding(binding); err != nil {
		return nil, false, err
	}
	if err := eventprotect.ValidateEnvelope(binding, postgresArtifactPolicyDigest(), envelope); err != nil {
		return nil, false, err
	}
	var opened []byte
	erased := false
	err := p.withCutLifetime(ctx, binding.TenantID, func(read context.Context, life Lifetime) error {
		if life.Activation == nil || life.Activation.Body.Creation.Ref.ID != envelope.KeyID {
			return ErrSource
		}
		var err error
		erased, err = p.withLifetimeKey(read, life, func(key seal.KeyWrapper) error {
			payload, err := eventprotect.Open(key, binding, postgresArtifactPolicyDigest(), envelope)
			if err != nil {
				return err
			}
			if payload.Actor != nil {
				secret.Wipe(payload.Data)
				return ErrSource
			}
			opened = payload.Data
			return nil
		})
		return err
	})
	if err != nil {
		secret.Wipe(opened)
		return nil, false, err
	}
	return opened, erased, nil
}

// RestorePlainPostgresRow applies only AFTER complete artifact authentication.
// V1 raw bytes remain legacy; logical omission never claims their crypto-erasure.
// A v2 plaintext row cannot stand in for an activated tenant's protected row.
func (p SourcePostgresProtection) RestorePlainPostgresRow(ctx context.Context, version int, cut uint64, tenant string, row json.RawMessage) (json.RawMessage, bool, error) {
	if cut != p.Cut || (version != 1 && version != 2) {
		return nil, false, ErrSource
	}
	erased := false
	err := p.withCutLifetime(ctx, tenant, func(read context.Context, life Lifetime) error {
		if life.Activation == nil {
			return p.Policy.withRegistrationFloor(read, life, p.Custody, func(_ context.Context, floor registrationFloor) error {
				if floor.erased {
					erased = true
					return nil
				}
				if floor.found || life.Request != nil {
					return ErrPreparing
				}
				return nil
			})
		}
		var err error
		erased, err = p.withLifetimeKey(read, life, func(seal.KeyWrapper) error { return nil })
		if err != nil {
			return err
		}
		if version == 2 {
			return ErrSource
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if erased {
		return nil, true, nil
	}
	return row, false, nil
}
