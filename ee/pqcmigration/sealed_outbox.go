// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/tenantseal"
)

const (
	tlsPostureSealedFormat  = "trstctl.pqc-tls-posture.sealed"
	tlsPostureSealedVersion = 1
)

type sealedTLSPostureOutbox struct {
	Format         string `json:"format"`
	Version        int    `json:"version"`
	RunID          string `json:"run_id"`
	AssetID        string `json:"asset_id"`
	TargetRevision string `json:"target_revision"`
	Sealed         []byte `json:"sealed"`
}

type tlsPostureCipher interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(container, aad []byte) ([]byte, error)
}

type tlsPostureKeyWrapperCipher struct{ key seal.KeyWrapper }

func (c tlsPostureKeyWrapperCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	return seal.Seal(c.key, plaintext, aad)
}

func (c tlsPostureKeyWrapperCipher) Open(container, aad []byte) ([]byte, error) {
	return seal.Open(c.key, container, aad)
}

type tlsPostureCipherContextKey struct{}

func withTLSPostureTenantCipher(ctx context.Context, access tenantseal.Access, key seal.KeyWrapper, tenantID string, fn func(context.Context, tlsPostureCipher) error) error {
	if cipher, ok := ctx.Value(tlsPostureCipherContextKey{}).(tenantseal.Cipher); ok {
		return fn(ctx, cipher)
	}
	if access != nil {
		return access.WithTenant(ctx, tenantID, func(cipher tenantseal.Cipher) error {
			return fn(context.WithValue(ctx, tlsPostureCipherContextKey{}, cipher), cipher)
		})
	}
	if key == nil {
		return errors.New("pqcmigration: TLS posture outbox requires a KEK")
	}
	return fn(ctx, tlsPostureKeyWrapperCipher{key: key})
}

func sealTLSPostureOutbox(key seal.KeyWrapper, tenantID, destination, idempotencyKey, runID, assetID, targetRevision string, payload any) ([]byte, error) {
	if key == nil {
		return nil, errors.New("pqcmigration: TLS posture outbox requires a KEK")
	}
	return sealTLSPostureOutboxWithCipher(tlsPostureKeyWrapperCipher{key: key}, tenantID, destination, idempotencyKey, runID, assetID, targetRevision, payload)
}

func sealTLSPostureOutboxForTenant(ctx context.Context, access tenantseal.Access, key seal.KeyWrapper, tenantID, destination, idempotencyKey, runID, assetID, targetRevision string, payload any) ([]byte, error) {
	var encoded []byte
	err := withTLSPostureTenantCipher(ctx, access, key, tenantID, func(_ context.Context, cipher tlsPostureCipher) (err error) {
		encoded, err = sealTLSPostureOutboxWithCipher(cipher, tenantID, destination, idempotencyKey, runID, assetID, targetRevision, payload)
		return err
	})
	return encoded, err
}

func sealTLSPostureOutboxWithCipher(cipher tlsPostureCipher, tenantID, destination, idempotencyKey, runID, assetID, targetRevision string, payload any) ([]byte, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(destination) == "" ||
		strings.TrimSpace(idempotencyKey) == "" || strings.TrimSpace(runID) == "" ||
		strings.TrimSpace(assetID) == "" || strings.TrimSpace(targetRevision) == "" {
		return nil, errors.New("pqcmigration: sealed TLS posture AAD fields are required")
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(plain)
	sealed, err := cipher.Seal(plain, tlsPostureAAD(tenantID, destination, idempotencyKey, runID, assetID, targetRevision))
	if err != nil {
		return nil, fmt.Errorf("pqcmigration: seal TLS posture outbox: %w", err)
	}
	return json.Marshal(sealedTLSPostureOutbox{
		Format: tlsPostureSealedFormat, Version: tlsPostureSealedVersion,
		RunID: strings.TrimSpace(runID), AssetID: strings.TrimSpace(assetID),
		TargetRevision: strings.TrimSpace(targetRevision), Sealed: sealed,
	})
}

func openTLSPostureOutbox(key seal.KeyWrapper, tenantID, destination, idempotencyKey string, payload []byte, out any) (sealedTLSPostureOutbox, error) {
	if key == nil {
		return sealedTLSPostureOutbox{}, errors.New("pqcmigration: TLS posture outbox requires a KEK")
	}
	return openTLSPostureOutboxWithCipher(tlsPostureKeyWrapperCipher{key: key}, tenantID, destination, idempotencyKey, payload, out)
}

func openTLSPostureOutboxForTenant(ctx context.Context, access tenantseal.Access, key seal.KeyWrapper, tenantID, destination, idempotencyKey string, payload []byte, out any) (sealedTLSPostureOutbox, error) {
	var wrapped sealedTLSPostureOutbox
	err := withTLSPostureTenantCipher(ctx, access, key, tenantID, func(_ context.Context, cipher tlsPostureCipher) (err error) {
		wrapped, err = openTLSPostureOutboxWithCipher(cipher, tenantID, destination, idempotencyKey, payload, out)
		return err
	})
	return wrapped, err
}

func openTLSPostureOutboxWithCipher(cipher tlsPostureCipher, tenantID, destination, idempotencyKey string, payload []byte, out any) (sealedTLSPostureOutbox, error) {
	var wrapped sealedTLSPostureOutbox
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		return wrapped, fmt.Errorf("pqcmigration: decode sealed TLS posture wrapper: %w", err)
	}
	if wrapped.Format != tlsPostureSealedFormat || wrapped.Version != tlsPostureSealedVersion ||
		wrapped.RunID == "" || wrapped.AssetID == "" || wrapped.TargetRevision == "" || len(wrapped.Sealed) == 0 {
		return wrapped, errors.New("pqcmigration: unsupported or incomplete sealed TLS posture wrapper")
	}
	plain, err := cipher.Open(wrapped.Sealed, tlsPostureAAD(
		tenantID, destination, idempotencyKey, wrapped.RunID, wrapped.AssetID, wrapped.TargetRevision,
	))
	if err != nil {
		return wrapped, fmt.Errorf("pqcmigration: open sealed TLS posture outbox: %w", err)
	}
	defer secret.Wipe(plain)
	if err := json.Unmarshal(plain, out); err != nil {
		return wrapped, fmt.Errorf("pqcmigration: decode sealed TLS posture intent: %w", err)
	}
	return wrapped, nil
}

func tlsPostureAAD(tenantID, destination, idempotencyKey, runID, assetID, targetRevision string) []byte {
	return []byte(strings.Join([]string{
		"pqc-tls-posture-outbox-v1",
		strings.TrimSpace(tenantID), strings.TrimSpace(destination), strings.TrimSpace(idempotencyKey),
		strings.TrimSpace(runID), strings.TrimSpace(assetID), strings.TrimSpace(targetRevision),
	}, "\x00"))
}
