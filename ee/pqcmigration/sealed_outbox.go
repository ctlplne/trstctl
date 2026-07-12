// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
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

func sealTLSPostureOutbox(key seal.KeyWrapper, tenantID, destination, idempotencyKey, runID, assetID, targetRevision string, payload any) ([]byte, error) {
	if key == nil {
		return nil, errors.New("pqcmigration: TLS posture outbox requires a KEK")
	}
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
	sealed, err := seal.Seal(key, plain, tlsPostureAAD(tenantID, destination, idempotencyKey, runID, assetID, targetRevision))
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
	var wrapped sealedTLSPostureOutbox
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		return wrapped, fmt.Errorf("pqcmigration: decode sealed TLS posture wrapper: %w", err)
	}
	if wrapped.Format != tlsPostureSealedFormat || wrapped.Version != tlsPostureSealedVersion ||
		wrapped.RunID == "" || wrapped.AssetID == "" || wrapped.TargetRevision == "" || len(wrapped.Sealed) == 0 {
		return wrapped, errors.New("pqcmigration: unsupported or incomplete sealed TLS posture wrapper")
	}
	if key == nil {
		return wrapped, errors.New("pqcmigration: TLS posture outbox requires a KEK")
	}
	plain, err := seal.Open(key, wrapped.Sealed, tlsPostureAAD(
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
