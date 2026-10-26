// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CertificateKeyAttestation is the retained evidence behind a certificate's
// device-bound custody claim: the device's attestation exactly as it was
// verified, the binding whose SHA-256 it signed, and the facts checked then.
type CertificateKeyAttestation struct {
	EventID                      string    `json:"event_id"`
	Source                       string    `json:"source"`
	Format                       string    `json:"format"`
	Credential                   []byte    `json:"credential"`
	Binding                      []byte    `json:"binding"`
	PublicKeySHA256              []byte    `json:"public_key_sha256"`
	AttestationCertificateSHA256 []byte    `json:"attestation_certificate_sha256"`
	TrustedRootsSHA256           []byte    `json:"trusted_roots_sha256"`
	VerifiedAt                   time.Time `json:"verified_at"`
}

// ErrCertificateKeyAttestationNotFound means the certificate carries no
// device-bound custody claim.
var ErrCertificateKeyAttestationNotFound = errors.New("store: certificate has no key attestation")

// ApplyCertificateDeviceCustodyTx projects certificate.custody.device_attested:
// the certificate's custody becomes the device-bound claim the attestation
// proves, together with its evidence. It refines a requester origin (the
// requester presented the key) into that narrower claim; any other custody
// already recorded is a conflict and is never overwritten.
func (s *Store) ApplyCertificateDeviceCustodyTx(ctx context.Context, tx pgx.Tx, tenantID, fingerprint,
	generatedBy string, attestation CertificateKeyAttestation) error {
	evidence, err := json.Marshal(attestation)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE certificates
		    SET key_origin = 'device', key_storage = 'device_bound', key_exportable = 'non_exportable',
		        key_generated_by = $3, key_origin_derivation = '', key_origin_proof_event_id = '',
		        key_attestation = $4::jsonb
		  WHERE tenant_id = $1 AND fingerprint = $2
		    AND (key_origin IN ('', 'requester', 'device') OR key_origin_derivation <> '')
		    AND key_storage IN ('', 'device_bound')
		    AND key_exportable IN ('', 'non_exportable')
		    AND key_generated_by IN ('', $3)`,
		tenantID, fingerprint, generatedBy, evidence)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM certificates WHERE tenant_id = $1 AND fingerprint = $2)`,
		tenantID, fingerprint).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return pgx.ErrNoRows
	}
	return fmt.Errorf("store: certificate device attestation conflicts with retained custody")
}

// GetCertificateKeyAttestation returns the retained device attestation for
// one certificate, by inventory ID.
func (s *Store) GetCertificateKeyAttestation(ctx context.Context, tenantID, certificateID string) (CertificateKeyAttestation, error) {
	var raw []byte
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT key_attestation FROM certificates WHERE tenant_id = $1 AND id = $2`,
			tenantID, certificateID).Scan(&raw)
	})
	if err != nil {
		return CertificateKeyAttestation{}, err
	}
	if len(raw) == 0 {
		return CertificateKeyAttestation{}, ErrCertificateKeyAttestationNotFound
	}
	var out CertificateKeyAttestation
	if err := json.Unmarshal(raw, &out); err != nil {
		return CertificateKeyAttestation{}, fmt.Errorf("store: decode certificate key attestation: %w", err)
	}
	return out, nil
}
