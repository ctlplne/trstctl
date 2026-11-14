// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// Factory provisioning (P12): the projections of edge.factory_batch.created,
// edge.factory_birth.recorded and edge.factory_device.enrolled.

// ErrFactoryBatchNotFound is a factory batch this tenant does not have.
var ErrFactoryBatchNotFound = errors.New("store: factory batch not found")

// FactoryBatch is one quota of birth certificates under one edge delegation.
type FactoryBatch struct {
	ID                 string
	DelegationID       string
	Label              string
	Quota              int
	BirthTTLSeconds    int
	OperationalProfile string
	CreatedBy          string
	CreatedAt          time.Time
	Recorded           int
	OverQuota          int
	// P12-L1: the device attestation roots, and births recorded without a
	// verified attestation.
	DeviceAttestationRootsPEM []string
	Unattested                int
}

// FactoryBirth is one birth certificate a station issued and a reconcile
// recorded, with the device's enrollment.
type FactoryBirth struct {
	BatchID                string
	Serial                 string
	DeviceName             string
	Fingerprint            string
	CertificateDER         []byte
	NotAfter               time.Time
	OverQuota              bool
	RecordedAt             time.Time
	Enrolled               bool
	EnrolledAt             *time.Time
	CSRSHA256              string
	OperationalSerial      string
	OperationalFingerprint string
	OperationalDER         []byte
	Renewals               int
	// Attestation (P12-L1): verified, missing or refused in a batch with
	// device attestation roots; empty otherwise.
	Attestation string
}

func factorySequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > math.MaxInt64 {
		return 0, fmt.Errorf("store: factory event sequence %d is out of range", sequence)
	}
	return int64(sequence), nil // #nosec G115 -- bounded above (CWE-190)
}

// ApplyFactoryBatchCreatedTx projects a new batch. A replay adds nothing.
func (s *Store) ApplyFactoryBatchCreatedTx(ctx context.Context, tx pgx.Tx, tenantID string, b FactoryBatch, sequence uint64) error {
	seq, err := factorySequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO factory_batches (tenant_id, id, delegation_id, label, quota, birth_ttl_seconds, operational_profile,
		                             created_by, created_at, event_sequence, device_attestation_roots)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID, b.ID, b.DelegationID, b.Label, b.Quota, b.BirthTTLSeconds, b.OperationalProfile, b.CreatedBy, b.CreatedAt.UTC(), seq,
		factoryRoots(b.DeviceAttestationRootsPEM))
	return err
}

// ApplyFactoryBirthRecordedTx projects one reconciled birth certificate and
// counts it on its batch. A replay adds nothing.
func (s *Store) ApplyFactoryBirthRecordedTx(ctx context.Context, tx pgx.Tx, tenantID string, b FactoryBirth, sequence uint64) error {
	seq, err := factorySequence(sequence)
	if err != nil {
		return err
	}
	// The table is also unique on (tenant, fingerprint): serialize identical
	// projections on the arbiter so a concurrent replay of the same birth meets
	// the ON CONFLICT row instead of a unique violation on the fingerprint
	// (OPP-C01).
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"factory-birth\x1f"+tenantID+"\x1f"+b.BatchID+"\x1f"+b.Serial); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO factory_birth_certificates (tenant_id, batch_id, serial, device_name, fingerprint, certificate_der, not_after,
		                                        over_quota, recorded_at, event_sequence, attestation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, batch_id, serial) DO NOTHING`,
		tenantID, b.BatchID, b.Serial, b.DeviceName, b.Fingerprint, b.CertificateDER, b.NotAfter.UTC(), b.OverQuota, b.RecordedAt.UTC(), seq,
		b.Attestation)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	over, unattested := 0, 0
	if b.OverQuota {
		over = 1
	}
	if b.Attestation == FactoryAttestationMissing || b.Attestation == FactoryAttestationRefused {
		unattested = 1
	}
	_, err = tx.Exec(ctx, `UPDATE factory_batches SET recorded = recorded + 1, over_quota = over_quota + $3, event_sequence = $4,
		unattested = unattested + $5
		WHERE tenant_id = $1 AND id = $2`, tenantID, b.BatchID, over, seq, unattested)
	return err
}

// ApplyFactoryDeviceEnrolledTx records a device's first boot or a renewal: its
// current operational certificate.
func (s *Store) ApplyFactoryDeviceEnrolledTx(ctx context.Context, tx pgx.Tx, tenantID, batchID, serial, csrSHA256,
	operationalSerial, operationalFingerprint string, operationalDER []byte, renewal bool, at time.Time, sequence uint64) error {
	seq, err := factorySequence(sequence)
	if err != nil {
		return err
	}
	renewals := 0
	if renewal {
		renewals = 1
	}
	_, err = tx.Exec(ctx, `UPDATE factory_birth_certificates SET enrolled = true, enrolled_at = coalesce(enrolled_at, $3),
		csr_sha256 = CASE WHEN $4 = '' THEN csr_sha256 ELSE $4 END, operational_serial = $5, operational_fingerprint = $6,
		operational_der = $7, renewals = renewals + $8, event_sequence = $9
		WHERE tenant_id = $1 AND serial = $2 AND batch_id = $10`,
		tenantID, serial, at.UTC(), csrSHA256, operationalSerial, operationalFingerprint, operationalDER, renewals, seq, batchID)
	return err
}

const factoryBatchColumns = `id::text, delegation_id, label, quota, birth_ttl_seconds, operational_profile, created_by, created_at,
	recorded, over_quota, device_attestation_roots, unattested`

func scanFactoryBatch(row pgx.Row) (FactoryBatch, error) {
	var b FactoryBatch
	err := row.Scan(&b.ID, &b.DelegationID, &b.Label, &b.Quota, &b.BirthTTLSeconds, &b.OperationalProfile, &b.CreatedBy,
		&b.CreatedAt, &b.Recorded, &b.OverQuota, &b.DeviceAttestationRootsPEM, &b.Unattested)
	if len(b.DeviceAttestationRootsPEM) == 0 {
		b.DeviceAttestationRootsPEM = nil
	}
	return b, err
}

// GetFactoryBatch reads one batch.
func (s *Store) GetFactoryBatch(ctx context.Context, tenantID, id string) (FactoryBatch, error) {
	var b FactoryBatch
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		b, err = scanFactoryBatch(tx.QueryRow(ctx, `SELECT `+factoryBatchColumns+` FROM factory_batches
			WHERE tenant_id = $1 AND id::text = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return FactoryBatch{}, ErrFactoryBatchNotFound
	}
	return b, err
}

// LockFactoryBatchTx reads a batch under a row lock, so births are counted
// against its quota one at a time.
func (s *Store) LockFactoryBatchTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (FactoryBatch, error) {
	b, err := scanFactoryBatch(tx.QueryRow(ctx, `SELECT `+factoryBatchColumns+` FROM factory_batches
		WHERE tenant_id = $1 AND id::text = $2 FOR UPDATE`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return FactoryBatch{}, ErrFactoryBatchNotFound
	}
	return b, err
}

// ListFactoryBatches lists the tenant's batches, newest first.
func (s *Store) ListFactoryBatches(ctx context.Context, tenantID string) ([]FactoryBatch, error) {
	out := []FactoryBatch{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+factoryBatchColumns+` FROM factory_batches WHERE tenant_id = $1
			ORDER BY created_at DESC, id LIMIT 500`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			b, err := scanFactoryBatch(rows)
			if err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

const factoryBirthColumns = `batch_id::text, serial, device_name, fingerprint, certificate_der, not_after, over_quota, recorded_at,
	enrolled, enrolled_at, csr_sha256, operational_serial, operational_fingerprint, coalesce(operational_der, ''::bytea), renewals,
	attestation`

func scanFactoryBirth(row pgx.Row) (FactoryBirth, error) {
	var b FactoryBirth
	err := row.Scan(&b.BatchID, &b.Serial, &b.DeviceName, &b.Fingerprint, &b.CertificateDER, &b.NotAfter, &b.OverQuota,
		&b.RecordedAt, &b.Enrolled, &b.EnrolledAt, &b.CSRSHA256, &b.OperationalSerial, &b.OperationalFingerprint,
		&b.OperationalDER, &b.Renewals, &b.Attestation)
	return b, err
}

// FactoryBirthExistsTx reports whether a batch already recorded this serial.
func (s *Store) FactoryBirthExistsTx(ctx context.Context, tx pgx.Tx, tenantID, batchID, serial string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM factory_birth_certificates
		WHERE tenant_id = $1 AND batch_id::text = $2 AND serial = $3)`, tenantID, batchID, serial).Scan(&exists)
	return exists, err
}

// FactoryBirthByFingerprint finds a birth certificate by its SHA-256, or a
// device by its current operational certificate's.
func (s *Store) FactoryBirthByFingerprint(ctx context.Context, tenantID, fingerprint string, operational bool) (FactoryBirth, bool, error) {
	column := "fingerprint"
	if operational {
		column = "operational_fingerprint"
	}
	var b FactoryBirth
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		b, err = scanFactoryBirth(tx.QueryRow(ctx, `SELECT `+factoryBirthColumns+` FROM factory_birth_certificates
			WHERE tenant_id = $1 AND `+column+` = $2 AND $2 <> ''`, tenantID, fingerprint))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	return b, found, err
}

// ListFactoryBirths lists a batch's birth certificates in recorded order.
func (s *Store) ListFactoryBirths(ctx context.Context, tenantID, batchID string, limit int) ([]FactoryBirth, error) {
	out := []FactoryBirth{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+factoryBirthColumns+` FROM factory_birth_certificates
			WHERE tenant_id = $1 AND batch_id::text = $2 ORDER BY event_sequence, serial LIMIT $3`, tenantID, batchID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			b, err := scanFactoryBirth(rows)
			if err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

// A birth's device attestation in a batch with device attestation roots
// (P12-L1). Only a verified one enrolls.
const (
	FactoryAttestationVerified = "verified"
	FactoryAttestationMissing  = "missing"
	FactoryAttestationRefused  = "refused"
)

// factoryRoots stores a batch's roots as a non-null array.
func factoryRoots(roots []string) []string {
	if roots == nil {
		return []string{}
	}
	return roots
}
