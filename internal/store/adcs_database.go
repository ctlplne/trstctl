// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// AD CS certificate-database summary read model (epic F4). A projection of
// adcs.ca_database.ingested: the domain-joined relay collects certutil rows,
// the control plane parses and summarizes them, and this table holds the latest
// per-disposition breakdown per CA — the lifecycle visibility issuance alone
// cannot give.

// ADCSDatabaseSummary is one CA's latest ingested certificate-database breakdown.
type ADCSDatabaseSummary struct {
	TenantID string
	CAConfig string
	Issued   int
	Pending  int
	Revoked  int
	Denied   int
	Failed   int
	Unknown  int
	// Unparsed counts issued rows whose expiry could not be read — a visibility
	// gap, not a healthy row.
	Unparsed     int
	Total        int
	RowsRead     int
	RowsRejected int
	Source       string
	LastError    string
	IngestedAt   time.Time
}

// ApplyADCSDatabaseIngestedTx projects adcs.ca_database.ingested. The event
// sequence guards it monotone so a delayed tail replay cannot move the row
// backward to an older sweep.
func (s *Store) ApplyADCSDatabaseIngestedTx(ctx context.Context, tx pgx.Tx, sum ADCSDatabaseSummary, eventSequence uint64) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO adcs_ca_databases
		        (tenant_id, ca_config, issued, pending, revoked, denied, failed, unknown,
		         unparsed, total, rows_read, rows_rejected, source, last_error, ingested_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		 ON CONFLICT (tenant_id, ca_config) DO UPDATE
		    SET issued = EXCLUDED.issued, pending = EXCLUDED.pending, revoked = EXCLUDED.revoked,
		        denied = EXCLUDED.denied, failed = EXCLUDED.failed, unknown = EXCLUDED.unknown,
		        unparsed = EXCLUDED.unparsed, total = EXCLUDED.total,
		        rows_read = EXCLUDED.rows_read, rows_rejected = EXCLUDED.rows_rejected,
		        source = EXCLUDED.source, last_error = EXCLUDED.last_error,
		        ingested_at = EXCLUDED.ingested_at, event_sequence = EXCLUDED.event_sequence
		  WHERE adcs_ca_databases.event_sequence <= EXCLUDED.event_sequence`,
		sum.TenantID, sum.CAConfig, sum.Issued, sum.Pending, sum.Revoked, sum.Denied,
		sum.Failed, sum.Unknown, sum.Unparsed, sum.Total, sum.RowsRead, sum.RowsRejected,
		sum.Source, sum.LastError, sum.IngestedAt.UTC(), eventSequence)
	return err
}

const adcsDatabaseCols = `tenant_id::text, ca_config, issued, pending, revoked, denied, failed,
	unknown, unparsed, total, rows_read, rows_rejected, source, last_error, ingested_at`

func scanADCSDatabaseSummary(row pgx.Row) (ADCSDatabaseSummary, error) {
	var s ADCSDatabaseSummary
	err := row.Scan(&s.TenantID, &s.CAConfig, &s.Issued, &s.Pending, &s.Revoked, &s.Denied,
		&s.Failed, &s.Unknown, &s.Unparsed, &s.Total, &s.RowsRead, &s.RowsRejected,
		&s.Source, &s.LastError, &s.IngestedAt)
	return s, err
}

// ListADCSDatabaseSummaries returns the tenant's CA-database summaries,
// pending-first so the CAs awaiting an approval decision surface at the top.
func (s *Store) ListADCSDatabaseSummaries(ctx context.Context, tenantID string) ([]ADCSDatabaseSummary, error) {
	var out []ADCSDatabaseSummary
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+adcsDatabaseCols+` FROM adcs_ca_databases
			  WHERE tenant_id = $1
			  ORDER BY pending DESC, ca_config`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sum, err := scanADCSDatabaseSummary(rows)
			if err != nil {
				return err
			}
			out = append(out, sum)
		}
		return rows.Err()
	})
	return out, err
}

// ADCSDatabaseCollection is one relay read of a CA database (A162), read from
// the queued command itself.
type ADCSDatabaseCollection struct {
	CollectionID string
	CAConfig     string
	AgentID      string
	// Status is queued, running, collected or failed.
	Status      string
	Attempts    int
	LastError   string
	RequestedAt time.Time
	CompletedAt *time.Time
}

// LockPendingADCSDatabaseCollectionTx serializes reads of one CA and reports
// whether one is already waiting or running.
func (s *Store) LockPendingADCSDatabaseCollectionTx(ctx context.Context, tx pgx.Tx, tenantID, caConfig string) (bool, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "adcs-ca-database\x1f"+tenantID+"\x1f"+caConfig); err != nil {
		return false, err
	}
	var pending bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS (
		    SELECT 1 FROM outbox
		     WHERE tenant_id = $1
		       AND destination = 'adcs.ca_database'
		       AND status IN ('pending', 'processing')
		       AND claim_completed_at IS NULL
		       AND convert_from(payload, 'UTF8')::jsonb ->> 'ca_config' = $2
		)`, tenantID, caConfig).Scan(&pending)
	return pending, err
}

// ListADCSDatabaseCollections returns the tenant's newest relay reads, newest
// first, with the status their queued command reached.
func (s *Store) ListADCSDatabaseCollections(ctx context.Context, tenantID string, limit int) ([]ADCSDatabaseCollection, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var out []ADCSDatabaseCollection
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT COALESCE(convert_from(payload, 'UTF8')::jsonb ->> 'id', ''),
			        COALESCE(convert_from(payload, 'UTF8')::jsonb ->> 'ca_config', ''),
			        COALESCE(convert_from(payload, 'UTF8')::jsonb ->> 'required_agent_id', ''),
			        CASE WHEN status = 'delivered' THEN 'collected'
			             WHEN status = 'failed' THEN 'failed'
			             WHEN claimed_by_agent_id IS NOT NULL AND claim_completed_at IS NULL THEN 'running'
			             ELSE 'queued' END,
			        attempts, COALESCE(last_error, ''), created_at, COALESCE(delivered_at, claim_completed_at)
			   FROM outbox
			  WHERE tenant_id = $1 AND destination = 'adcs.ca_database'
			  ORDER BY id DESC
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c ADCSDatabaseCollection
			if err := rows.Scan(&c.CollectionID, &c.CAConfig, &c.AgentID, &c.Status, &c.Attempts,
				&c.LastError, &c.RequestedAt, &c.CompletedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// ADCSRelayRevocation is where one AD CS revocation stands with its relay
// (A162), read from the queued attempts themselves.
type ADCSRelayRevocation struct {
	// Delivered: an attempt's report was checked and closed the job.
	Delivered bool
	// Pending: the newest attempt is waiting for, or held by, the relay.
	Pending bool
	// Failed counts attempts the relay answered with a failure.
	Failed int
	// LastError is the newest failed attempt's reason.
	LastError string
}

// ADCSRelayRevocationState reads the relay attempts of one revocation.
func (s *Store) ADCSRelayRevocationState(ctx context.Context, tenantID, revocationID string) (ADCSRelayRevocation, error) {
	var out ADCSRelayRevocation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT status, COALESCE(last_error, ''), claim_completed_at IS NULL
			   FROM outbox
			  WHERE tenant_id = $1 AND destination = 'adcs.revoke'
			    AND convert_from(payload, 'UTF8')::jsonb ->> 'id' = $2
			  ORDER BY id`, tenantID, revocationID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var status, lastError string
			var open bool
			if err := rows.Scan(&status, &lastError, &open); err != nil {
				return err
			}
			out.Pending = false
			switch {
			case status == "delivered":
				out.Delivered = true
			case status == "failed":
				out.Failed++
				out.LastError = lastError
			case open:
				out.Pending = true
			}
		}
		return rows.Err()
	})
	return out, err
}
