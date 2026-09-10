// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/jackc/pgx/v5"
)

// LockCertificateRecordingTx serializes even the first record, when no row yet
// exists. The transaction is already tenant/RLS scoped; this lock does not
// replace that boundary. Hash collisions only serialize unrelated fingerprints.
func (s *Store) LockCertificateRecordingTx(ctx context.Context, tx pgx.Tx, tenantID, fingerprint string) error {
	if tenantID == "" || fingerprint == "" {
		return errors.New("store: certificate recording requires tenant and fingerprint")
	}
	var scoped bool
	if err := tx.QueryRow(ctx,
		`SELECT current_setting('trstctl.tenant_id',true)::uuid = $1::uuid`, tenantID).Scan(&scoped); err != nil {
		return err
	}
	if !scoped {
		return errors.New("store: certificate recording tenant differs from transaction scope (AN-1)")
	}
	// Live writers must take the relation lock before the fingerprint lock.
	// Otherwise a rebuild could hold the table and wait on our fingerprint
	// while we hold that fingerprint and wait on its table: a lock inversion.
	if _, err := tx.Exec(ctx, `LOCK TABLE certificates IN ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	if err := s.LockCertificateMetadataOrderTx(ctx, tx, tenantID); err != nil {
		return err
	}
	var ownsWholeTable bool
	//trstctl:system-query — inspect only this backend's granted lock on the routed certificate relation; no tenant data or other backend identity is selected (AN-1 exemption).
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='relation'
		AND relation='certificates'::regclass AND mode='AccessExclusiveLock' AND granted
	)`).Scan(&ownsWholeTable); err != nil {
		return err
	}
	if ownsWholeTable {
		// Atomic rebuild/restore already excludes every other certificate
		// writer. Do not retain one extra advisory lock per replayed leaf.
		return nil
	}
	// PostgreSQL UUID spelling is canonical, so upper/lowercase spellings of
	// one tenant cannot acquire different locks for the same stored row.
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
		'certificate-recording' || chr(31) || $1::uuid::text || chr(31) || $2::text,0))`, tenantID, fingerprint)
	return err
}

// ErrCertificateRecordingRebuildRequired distinguishes an upgraded old row from
// a first record. Replaying only certificate events over an old row could erase
// newer ownership projections; a complete ordered rebuild is required instead.
var ErrCertificateRecordingRebuildRequired = errors.New("store: certificate recording requires a full retained read-model rebuild")

type CertificateRecordingHead struct {
	EventID  string
	Sequence uint64
	Exists   bool
}

func (s *Store) CertificateRecordingHeadTx(ctx context.Context, tx pgx.Tx, tenantID, fingerprint string) (CertificateRecordingHead, error) {
	var head CertificateRecordingHead
	var seq int64
	err := tx.QueryRow(ctx,
		`SELECT recording_event_id,recording_sequence FROM certificates WHERE tenant_id=$1 AND fingerprint=$2`,
		tenantID, fingerprint).Scan(&head.EventID, &seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return head, nil
	}
	if err != nil {
		return head, err
	}
	if seq < 0 || (seq > 0 && head.EventID == "") {
		return head, errors.New("store: invalid certificate recording cursor")
	}
	head.Sequence, head.Exists = uint64(seq), true
	return head, nil
}

// ApplyCertificateRecordingHeadTx runs only after the projector's effects for
// this exact event succeed in the same transaction. SQL rollback cannot erase
// the source event that command recovery must replay before its next append.
func (s *Store) ApplyCertificateRecordingHeadTx(ctx context.Context, tx pgx.Tx, tenantID, fingerprint, eventID string, sequence uint64, issued bool) error {
	// An unsequenced projection cannot establish an immutable log origin or
	// a recovery checkpoint. Only events actually returned by the log can.
	if sequence == 0 {
		return nil
	}
	if sequence > math.MaxInt64 || eventID == "" {
		return errors.New("store: invalid certificate event cursor")
	}
	tag, err := tx.Exec(ctx, `UPDATE certificates SET recording_event_id=$3,recording_sequence=$4,
		issuance_event_id=CASE WHEN issuance_event_id='' AND $5::boolean THEN $3 ELSE issuance_event_id END
		WHERE tenant_id=$1 AND fingerprint=$2 AND recording_sequence<$4`,
		tenantID, fingerprint, eventID, int64(sequence), issued)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("store: certificate recording cursor did not advance")
	}
	return nil
}

// ValidateCertificateIssuanceBindingTx runs after missing source events have
// been recovered, under the same fingerprint transaction lock as the append.
// Empty ordinary import fields update metadata without replacing public output.
func (s *Store) ValidateCertificateIssuanceBindingTx(ctx context.Context, tx pgx.Tx, tenantID string, in Certificate) error {
	var retainedKey, binding string
	var der, public []byte
	err := tx.QueryRow(ctx, `SELECT issuance_idempotency_key,issuance_request_binding,certificate_der,certificate_pem
		FROM certificates WHERE tenant_id=$1 AND fingerprint=$2`, tenantID, in.Fingerprint).
		Scan(&retainedKey, &binding, &der, &public)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.HasPrefix(retainedKey, "broker-issue:") &&
		((in.IssuanceIdempotencyKey != "" && in.IssuanceIdempotencyKey != retainedKey) ||
			(in.IssuanceRequestBinding != "" && in.IssuanceRequestBinding != binding)) {
		return fmt.Errorf("%w: certificate broker binding differs", ErrIdempotencyConflict)
	}
	if strings.HasPrefix(retainedKey, "issue:transition:") &&
		((in.IssuanceIdempotencyKey != "" && in.IssuanceIdempotencyKey != retainedKey) ||
			(len(in.CertificatePEM) > 0 && len(public) > 0 && !bytes.Equal(in.CertificatePEM, public)) ||
			(len(in.CertificateDER) > 0 && len(der) > 0 && !bytes.Equal(in.CertificateDER, der))) {
		return fmt.Errorf("%w: certificate issuance key or public material differs", ErrIdempotencyConflict)
	}
	return nil
}
