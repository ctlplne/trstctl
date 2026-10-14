// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// CertificateRevocationAuthorityTarget is an exact issuer/serial, not an
// inventory label. Only locally served authority targets enter this receiver.
type CertificateRevocationAuthorityTarget struct {
	CAID, Serial, Fingerprint string
}

type CertificateRevocationAuthorityCommand struct {
	Event          events.Event
	RequestBinding string
	Status         string
	Targets        []CertificateRevocationAuthorityTarget
}

const certificateRevocationAuthorityColumns = `tenant_id::text,event_id,event_type,
	event_time,event_schema_version,event_payload,payload_sha256,request_binding,status,projected_sequence`

func scanCertificateRevocationAuthorityCommand(row pgx.Row) (CertificateRevocationAuthorityCommand, error) {
	var command CertificateRevocationAuthorityCommand
	var digest *string
	var sequence *int64
	if err := row.Scan(&command.Event.TenantID, &command.Event.ID, &command.Event.Type,
		&command.Event.Time, &command.Event.SchemaVersion, &command.Event.Data,
		&digest, &command.RequestBinding, &command.Status, &sequence); err != nil {
		return command, err
	}
	switch command.Status {
	case "pending":
		if digest == nil || len(command.Event.Data) == 0 || sequence != nil ||
			crypto.SHA256Hex(command.Event.Data) != *digest {
			return command, errors.New("store: pending certificate revocation command drifted")
		}
	case "completed":
		if digest != nil || len(command.Event.Data) != 0 || sequence == nil || *sequence <= 0 {
			return command, errors.New("store: completed certificate revocation command retained payload")
		}
		command.Event.Sequence = uint64(*sequence)
	default:
		return command, errors.New("store: invalid certificate revocation command status")
	}
	return command, nil
}

// ClaimCertificateRevocationAuthority commits a denial before broker append.
// A different event cannot seize an issuer/serial already held by the first.
func (s *Store) ClaimCertificateRevocationAuthority(ctx context.Context, candidate CertificateRevocationAuthorityCommand) (CertificateRevocationAuthorityCommand, error) {
	var canonical CertificateRevocationAuthorityCommand
	if candidate.Event.TenantID == "" || candidate.Event.ID == "" ||
		(candidate.Event.Type != "certificate.revocation.batch.applied" && candidate.Event.Type != "certificate.revoked") ||
		candidate.Event.SchemaVersion <= 0 || len(candidate.Event.Data) == 0 ||
		candidate.Event.Time.IsZero() || !candidate.Event.Time.Equal(candidate.Event.Time.UTC().Truncate(time.Microsecond)) ||
		len(candidate.RequestBinding) != 64 || len(candidate.Targets) == 0 || len(candidate.Targets) > 100 {
		return canonical, errors.New("store: incomplete certificate revocation authority command")
	}
	targets := append([]CertificateRevocationAuthorityTarget(nil), candidate.Targets...)
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].CAID != targets[j].CAID {
			return targets[i].CAID < targets[j].CAID
		}
		return targets[i].Serial < targets[j].Serial
	})
	for i, target := range targets {
		if target.CAID == "" || target.Serial == "" || len(target.Fingerprint) != 64 ||
			(i > 0 && target.CAID == targets[i-1].CAID && target.Serial == targets[i-1].Serial) {
			return canonical, errors.New("store: invalid certificate revocation authority target")
		}
	}
	err := s.WithTenant(ctx, candidate.Event.TenantID, func(tx pgx.Tx) error {
		if err := lockUpsertArbiterTx(ctx, tx, "certificate_revocation_authority_commands",
			candidate.Event.TenantID, candidate.Event.ID); err != nil {
			return err
		}
		var err error
		canonical, err = scanCertificateRevocationAuthorityCommand(tx.QueryRow(ctx,
			`SELECT `+certificateRevocationAuthorityColumns+` FROM certificate_revocation_authority_commands
			 WHERE tenant_id=$1 AND event_id=$2 FOR UPDATE`, candidate.Event.TenantID, candidate.Event.ID))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			if canonical.Status != "pending" || canonical.RequestBinding != candidate.RequestBinding ||
				canonical.Event.Type != candidate.Event.Type ||
				canonical.Event.SchemaVersion != candidate.Event.SchemaVersion ||
				!bytes.Equal(canonical.Event.Data, candidate.Event.Data) {
				return ErrIdempotencyConflict
			}
			rows, readErr := tx.Query(ctx, `SELECT ca_id::text,serial,fingerprint
				FROM certificate_revocation_authority_fences
				WHERE tenant_id=$1 AND event_id=$2 ORDER BY ca_id,serial`,
				candidate.Event.TenantID, candidate.Event.ID)
			if readErr != nil {
				return readErr
			}
			defer rows.Close()
			for rows.Next() {
				var target CertificateRevocationAuthorityTarget
				if err := rows.Scan(&target.CAID, &target.Serial, &target.Fingerprint); err != nil {
					return err
				}
				canonical.Targets = append(canonical.Targets, target)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if len(canonical.Targets) != len(targets) {
				return ErrIdempotencyConflict
			}
			for i := range targets {
				if canonical.Targets[i] != targets[i] {
					return ErrIdempotencyConflict
				}
			}
			return nil
		}
		_, err = tx.Exec(ctx, `INSERT INTO certificate_revocation_authority_commands
			(tenant_id,event_id,event_type,event_time,event_schema_version,event_payload,
			 payload_sha256,request_binding)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, candidate.Event.TenantID,
			candidate.Event.ID, candidate.Event.Type, candidate.Event.Time,
			candidate.Event.SchemaVersion, candidate.Event.Data,
			crypto.SHA256Hex(candidate.Event.Data), candidate.RequestBinding)
		if err != nil {
			return err
		}
		for _, target := range targets {
			if _, err := tx.Exec(ctx, `INSERT INTO certificate_revocation_authority_fences
				(tenant_id,ca_id,serial,fingerprint,event_id) VALUES ($1,$2,$3,$4,$5)`,
				candidate.Event.TenantID, target.CAID, target.Serial, target.Fingerprint,
				candidate.Event.ID); err != nil {
				return fmt.Errorf("%w: issuer serial already has a revocation decision: %v", ErrIdempotencyConflict, err)
			}
		}
		canonical = candidate
		canonical.Status = "pending"
		canonical.Targets = targets
		return nil
	})
	return canonical, err
}

func (s *Store) CertificateRevocationAuthorityCommandByEventID(ctx context.Context, tenantID, eventID string) (CertificateRevocationAuthorityCommand, error) {
	var command CertificateRevocationAuthorityCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var readErr error
		command, readErr = scanCertificateRevocationAuthorityCommand(tx.QueryRow(ctx,
			`SELECT `+certificateRevocationAuthorityColumns+` FROM certificate_revocation_authority_commands
			 WHERE tenant_id=$1 AND event_id=$2`, tenantID, eventID))
		return readErr
	})
	return command, err
}

func (s *Store) PendingCertificateRevocationForSerial(ctx context.Context, tenantID, caID, serial string) (bool, error) {
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM certificate_revocation_authority_fences
			WHERE tenant_id=$1 AND ca_id=$2 AND serial=$3 AND status='pending')`,
			tenantID, caID, serial).Scan(&pending)
	})
	return pending, err
}

func (s *Store) PendingCertificateRevocationForCA(ctx context.Context, tenantID, caID string) (bool, error) {
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM certificate_revocation_authority_fences
			WHERE tenant_id=$1 AND ca_id=$2 AND status='pending')`, tenantID, caID).Scan(&pending)
	})
	return pending, err
}

// PendingCertificateRevocationFingerprints backs inventory list/detail with a
// single tenant-scoped indexed read. A pending exact issuer decision is shown
// even when the certificate projection still says active.
func (s *Store) PendingCertificateRevocationFingerprints(ctx context.Context, tenantID string, fingerprints []string) (map[string]bool, error) {
	result := make(map[string]bool)
	if len(fingerprints) == 0 {
		return result, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT fingerprint FROM certificate_revocation_authority_fences
			WHERE tenant_id=$1 AND status='pending' AND fingerprint=ANY($2::text[])`, tenantID, fingerprints)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var fingerprint string
			if err := rows.Scan(&fingerprint); err != nil {
				return err
			}
			result[fingerprint] = true
		}
		return rows.Err()
	})
	return result, err
}

// CompleteCertificateRevocationAuthorityTx releases the pending status only
// in the transaction that updates issuer state and publication intent.
func (s *Store) CompleteCertificateRevocationAuthorityTx(ctx context.Context, tx pgx.Tx, event events.Event) error {
	if event.Sequence == 0 || event.Sequence > math.MaxInt64 {
		return errors.New("store: certificate revocation completion needs source sequence")
	}
	command, err := scanCertificateRevocationAuthorityCommand(tx.QueryRow(ctx,
		`SELECT `+certificateRevocationAuthorityColumns+` FROM certificate_revocation_authority_commands
		 WHERE tenant_id=$1 AND event_id=$2 FOR UPDATE`, event.TenantID, event.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // Historical event predates this authority receiver.
	}
	if err != nil {
		return err
	}
	if command.Status == "completed" {
		if command.Event.Sequence != event.Sequence {
			return ErrIdempotencyConflict
		}
		return nil
	}
	if command.Event.Type != event.Type || command.Event.SchemaVersion != event.SchemaVersion ||
		!command.Event.Time.Equal(event.Time) || !bytes.Equal(command.Event.Data, event.Data) {
		return fmt.Errorf("%w: certificate revocation differs from first command", ErrIdempotencyConflict)
	}
	if _, err := tx.Exec(ctx, `UPDATE certificate_revocation_authority_fences SET
		status='completed',projected_sequence=$3 WHERE tenant_id=$1 AND event_id=$2 AND status='pending'`,
		event.TenantID, event.ID, int64(event.Sequence)); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE certificate_revocation_authority_commands SET
		status='completed',event_payload=NULL,payload_sha256=NULL,
		projected_sequence=$3,updated_at=now()
		WHERE tenant_id=$1 AND event_id=$2 AND status='pending'`,
		event.TenantID, event.ID, int64(event.Sequence))
	return err
}

func (s *Store) PendingCertificateRevocationKeysSystem(ctx context.Context, afterTenant, afterEvent string, limit int) ([][2]string, error) {
	if afterTenant == "" {
		afterTenant = "00000000-0000-0000-0000-000000000000"
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	//trstctl:system-query — startup inventory exposes only tenant/event keys, not certificate data.
	rows, err := s.SystemPool().Query(ctx, `SELECT tenant_id::text,event_id FROM certificate_revocation_authority_commands
		WHERE status='pending' AND (tenant_id,event_id) > ($1::uuid,$2)
		ORDER BY tenant_id,event_id LIMIT $3`, afterTenant, afterEvent, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys [][2]string
	for rows.Next() {
		var key [2]string
		if err := rows.Scan(&key[0], &key[1]); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}
