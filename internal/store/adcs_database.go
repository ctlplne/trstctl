// SPDX-License-Identifier: MPL-2.0

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
// backwards to an older sweep.
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
