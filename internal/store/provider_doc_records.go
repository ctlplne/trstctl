// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// Documentation record sync states (MSP-14).
const (
	DocRecordSynced = "synced"
	DocRecordFailed = "failed"
)

// DocRecord is one customer's record in one documentation target.
type DocRecord struct {
	TenantID      string
	TargetID      string
	OrgID         string
	RecordID      string
	Digest        string
	Certificates  int
	NextExpiry    *time.Time
	Status        string
	Reason        string
	SyncedAt      *time.Time
	EventSequence uint64
	UpdatedAt     time.Time
}

// DocRecordChange is one projected sync outcome: a success replaces what
// the record holds; a failure keeps it and says why.
type DocRecordChange struct {
	TenantID     string
	TargetID     string
	OrgID        string
	RecordID     string
	Digest       string
	Certificates int
	NextExpiry   *time.Time
	OK           bool
	Reason       string
	At           time.Time
}

// ApplyDocRecordTx projects one sync outcome.
func (s *Store) ApplyDocRecordTx(ctx context.Context, tx pgx.Tx, c DocRecordChange, sequence uint64) error {
	if sequence == 0 || sequence > math.MaxInt64 {
		return errors.New("store: documentation record event sequence is out of range")
	}
	seq := int64(sequence) // #nosec G115 -- bounded by the check above (CWE-190)
	at := c.At.UTC()
	if c.OK {
		_, err := tx.Exec(ctx, `INSERT INTO provider_doc_records (tenant_id, target_id, org_id, record_id, digest, certificates, next_expiry, status,
			reason, synced_at, event_sequence, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'synced', '', $8, $9, $8)
			ON CONFLICT (tenant_id, target_id) DO UPDATE SET org_id = EXCLUDED.org_id, record_id = EXCLUDED.record_id, digest = EXCLUDED.digest,
			  certificates = EXCLUDED.certificates, next_expiry = EXCLUDED.next_expiry, status = 'synced', reason = '', synced_at = EXCLUDED.synced_at,
			  event_sequence = EXCLUDED.event_sequence, updated_at = EXCLUDED.updated_at
			WHERE provider_doc_records.event_sequence < EXCLUDED.event_sequence`,
			c.TenantID, c.TargetID, c.OrgID, c.RecordID, c.Digest, c.Certificates, c.NextExpiry, at, seq)
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO provider_doc_records (tenant_id, target_id, org_id, status, reason, event_sequence, updated_at)
		VALUES ($1, $2, $3, 'failed', $4, $5, $6)
		ON CONFLICT (tenant_id, target_id) DO UPDATE SET status = 'failed', reason = EXCLUDED.reason, event_sequence = EXCLUDED.event_sequence,
		  updated_at = EXCLUDED.updated_at
		WHERE provider_doc_records.event_sequence < EXCLUDED.event_sequence`,
		c.TenantID, c.TargetID, c.OrgID, c.Reason, seq, at)
	return err
}

const docRecordColumns = `tenant_id::text, target_id, org_id, record_id, digest, certificates, next_expiry, status, reason, synced_at,
	event_sequence, updated_at`

func scanDocRecord(row interface{ Scan(...any) error }) (DocRecord, error) {
	var r DocRecord
	var seq int64
	if err := row.Scan(&r.TenantID, &r.TargetID, &r.OrgID, &r.RecordID, &r.Digest, &r.Certificates, &r.NextExpiry, &r.Status, &r.Reason,
		&r.SyncedAt, &seq, &r.UpdatedAt); err != nil {
		return DocRecord{}, err
	}
	if seq > 0 {
		r.EventSequence = uint64(seq)
	}
	r.UpdatedAt = r.UpdatedAt.UTC()
	return r, nil
}

// DocRecordFor reads one customer's record in one target.
func (s *Store) DocRecordFor(ctx context.Context, tenantID, targetID string) (DocRecord, bool, error) {
	var out DocRecord
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		r, err := scanDocRecord(tx.QueryRow(ctx, `SELECT `+docRecordColumns+` FROM provider_doc_records WHERE tenant_id = $1 AND target_id = $2`,
			tenantID, targetID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		out, found = r, err == nil
		return err
	})
	return out, found, err
}

// DocRecords reads a customer's records, by target.
func (s *Store) DocRecords(ctx context.Context, tenantID string, limit int) ([]DocRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var out []DocRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+docRecordColumns+` FROM provider_doc_records WHERE tenant_id = $1 ORDER BY target_id LIMIT $2`,
			tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanDocRecord(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// DocCertificate is one certificate a documentation record lists.
type DocCertificate struct {
	Subject  string
	SANs     []string
	Issuer   string
	Serial   string
	NotAfter *time.Time
	Location string
}

// DocRecordCertificates reads a customer's active certificates (ephemeral
// issuances left out), soonest expiry first, at most limit, and how many
// there are in all.
func (s *Store) DocRecordCertificates(ctx context.Context, tenantID string, limit int) ([]DocCertificate, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var out []DocCertificate
	total := 0
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE tenant_id = $1 AND status = 'active'
			AND issuance_idempotency_key NOT LIKE 'ephemeral-issue:%'`, tenantID).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT subject, sans, issuer, serial, not_after, deployment_location FROM certificates
			WHERE tenant_id = $1 AND status = 'active' AND issuance_idempotency_key NOT LIKE 'ephemeral-issue:%'
			ORDER BY not_after ASC NULLS LAST, id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c DocCertificate
			if err := rows.Scan(&c.Subject, &c.SANs, &c.Issuer, &c.Serial, &c.NotAfter, &c.Location); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, total, err
}
