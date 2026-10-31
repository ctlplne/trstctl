// SPDX-License-Identifier: BUSL-1.1
package eventprivacy

import (
	"context"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

type SnapshotArtifactCustody interface {
	VerifiedCustody
	ErasurePlanCustody
	registrationCustody
}

// SourceSnapshotProtection opens the creation selected by the exact captured
// source cut. Each chunk holds at most one bounded key fence; no key survives a
// callback and no snapshot grants provisioning, destruction or a source append.
type SourceSnapshotProtection struct {
	Policy  SourcePolicy
	Custody SnapshotArtifactCustody
}

func (p SourceSnapshotProtection) operation(binding eventprotect.Context) (SourcePostgresProtection, error) {
	parts := strings.Split(binding.ID, ":")
	if binding.Scope != eventprotect.ScopeSnapshot || binding.Type != "read_model_snapshot" || binding.SchemaVersion != store.SnapshotFormatVersion || binding.Time.IsZero() || len(parts) != 4 {
		return SourcePostgresProtection{}, ErrSource
	}
	capture, err := uuid.Parse(parts[0])
	if err != nil || capture.Version() != 4 || capture.String() != parts[0] {
		return SourcePostgresProtection{}, ErrSource
	}
	cut, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || cut == 0 || strconv.FormatUint(cut, 10) != parts[1] {
		return SourcePostgresProtection{}, ErrSource
	}
	ordinal, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || ordinal == 0 || strconv.FormatUint(ordinal, 10) != parts[2] || len(parts[3]) != 64 || strings.ToLower(parts[3]) != parts[3] {
		return SourcePostgresProtection{}, ErrSource
	}
	if _, err := hex.DecodeString(parts[3]); err != nil {
		return SourcePostgresProtection{}, ErrSource
	}
	tenant, err := uuid.Parse(binding.TenantID)
	if err != nil || tenant == uuid.Nil || tenant.String() != binding.TenantID {
		return SourcePostgresProtection{}, ErrSource
	}
	return SourcePostgresProtection{Policy: p.Policy, Custody: p.Custody, Cut: cut}, nil
}

func snapshotSourcePolicyDigest() string {
	return crypto.SHA256Hex([]byte(store.SnapshotProtectionPolicyDomain))
}

func (p SourceSnapshotProtection) ProtectSnapshotChunk(ctx context.Context, binding eventprotect.Context, raw []byte) (eventprotect.Envelope, bool, error) {
	operation, err := p.operation(binding)
	if err != nil {
		return eventprotect.Envelope{}, false, err
	}
	var envelope eventprotect.Envelope
	protected := false
	err = operation.withCutLifetime(ctx, binding.TenantID, func(read context.Context, life Lifetime) error {
		if life.Registration.ID == "" {
			return ErrSource
		}
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
		erased, err := operation.withLifetimeKey(read, life, func(key seal.KeyWrapper) error {
			var err error
			envelope, err = eventprotect.Protect(key, binding, life.Activation.Body.Creation.Ref.ID, snapshotSourcePolicyDigest(), eventprotect.Payload{Data: raw})
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

func (p SourceSnapshotProtection) OpenSnapshotChunk(ctx context.Context, binding eventprotect.Context, envelope eventprotect.Envelope) ([]byte, bool, error) {
	operation, err := p.operation(binding)
	if err != nil {
		return nil, false, err
	}
	if err := eventprotect.ValidateEnvelope(binding, snapshotSourcePolicyDigest(), envelope); err != nil {
		return nil, false, err
	}
	var opened []byte
	erased := false
	err = operation.withCutLifetime(ctx, binding.TenantID, func(read context.Context, life Lifetime) error {
		if life.Activation == nil || life.Activation.Body.Creation.Ref.ID != envelope.KeyID {
			return ErrSource
		}
		var err error
		erased, err = operation.withLifetimeKey(read, life, func(key seal.KeyWrapper) error {
			payload, err := eventprotect.Open(key, binding, snapshotSourcePolicyDigest(), envelope)
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

func (p SourceSnapshotProtection) RestorePlainSnapshot(ctx context.Context, binding eventprotect.Context, raw []byte) (bool, error) {
	operation, err := p.operation(binding)
	if err != nil {
		return false, err
	}
	erased := false
	err = operation.withCutLifetime(ctx, binding.TenantID, func(read context.Context, life Lifetime) error {
		if life.Registration.ID == "" {
			return ErrSource
		}
		var err error
		_, erased, err = operation.RestorePlainPostgresRow(read, 2, operation.Cut, binding.TenantID, raw)
		return err
	})
	return erased, err
}
