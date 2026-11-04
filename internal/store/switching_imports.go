// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// Switching imports (A265): another certificate-management product's export,
// mapped row by row and recorded, the projections of the switching.import.*
// events. A row keeps the export's metadata and its outcome; the certificate it
// records goes through certificate.recorded.

// ErrSwitchingImportNotFound is an import this tenant does not have.
var ErrSwitchingImportNotFound = errors.New("store: switching import not found")

// SwitchingImport is one import's header and progress.
type SwitchingImport struct {
	ID            string
	Name          string
	Format        string
	PreviewDigest string
	RowsTotal     int
	Counts        map[string]int
	GapCounts     map[string]int
	RowsRecorded  int
	RowsApplied   int
	Status        string
	CreatedBy     string
	CreatedAt     time.Time
	CompletedAt   *time.Time
	// The endpoint watch: the current round, the rows it has not observed
	// yet, and the private egress the operator granted it.
	WatchRound        int
	WatchPending      int
	WatchAllowPrivate bool
	WatchPrivateCIDRs []string
	WatchRequestedAt  *time.Time
	WatchRequestedBy  string
}

// SwitchingImportRow is one export row's outcome and what it became.
type SwitchingImportRow struct {
	Row          int        `json:"row_number"`
	Outcome      string     `json:"outcome"`
	Gaps         []string   `json:"gaps"`
	Reason       string     `json:"reason"`
	DuplicateOf  *int       `json:"duplicate_of,omitempty"`
	Fingerprint  string     `json:"fingerprint"`
	CommonName   string     `json:"common_name"`
	SANs         []string   `json:"sans"`
	KeyAlgorithm string     `json:"key_algorithm"`
	Serial       string     `json:"serial"`
	Issuer       string     `json:"issuer"`
	NotAfter     *time.Time `json:"not_after,omitempty"`
	Folder       string     `json:"folder"`
	Profile      string     `json:"profile"`
	Application  string     `json:"application"`
	OwnerEmail   string     `json:"owner_email"`
	Endpoints    []string   `json:"endpoints"`
	// CertificateDER is the public certificate when the export carried it.
	CertificateDER []byte     `json:"certificate_der,omitempty"`
	CertificateID  string     `json:"-"`
	OwnerID        string     `json:"-"`
	Linked         bool       `json:"-"`
	AppliedAt      *time.Time `json:"-"`
	// The last watch round's observation of the row's endpoints.
	WatchRound        int        `json:"-"`
	WatchStatus       string     `json:"-"`
	WatchEndpoint     string     `json:"-"`
	ServedFingerprint string     `json:"-"`
	WatchDetail       string     `json:"-"`
	WatchedAt         *time.Time `json:"-"`
}

// Watch statuses of a row: what its endpoints served at the last round.
const (
	SwitchingWatchMatched     = "matched"
	SwitchingWatchServesOther = "serves_other"
	SwitchingWatchUnreachable = "unreachable"
	SwitchingWatchNoEndpoint  = "no_endpoint"
	// A row in a live renewal wave: its endpoint serves the certificate
	// trstctl issued, or one neither the export nor trstctl holds.
	SwitchingWatchServesTrstctl         = "serves_trstctl"
	SwitchingWatchRenewedByOtherProduct = "renewed_by_other_product"
)

// SwitchingWatchResult is one row's observation in a watch round.
type SwitchingWatchResult struct {
	Row               int    `json:"row_number"`
	Status            string `json:"status"`
	Endpoint          string `json:"endpoint"`
	ServedFingerprint string `json:"served_fingerprint"`
	Detail            string `json:"detail"`
}

// SwitchingRowApplied is what one applied row became. Linked is a row whose
// certificate was already in the inventory: it is linked, never rewritten.
type SwitchingRowApplied struct {
	Row           int    `json:"row_number"`
	CertificateID string `json:"certificate_id"`
	OwnerID       string `json:"owner_id"`
	Linked        bool   `json:"linked"`
}

func switchingSequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > math.MaxInt64 {
		return 0, fmt.Errorf("store: switching import event sequence %d is out of range", sequence)
	}
	return int64(sequence), nil // #nosec G115 -- bounded above (CWE-190)
}

// ApplySwitchingImportStartedTx projects a started import.
func (s *Store) ApplySwitchingImportStartedTx(ctx context.Context, tx pgx.Tx, tenantID string, imp SwitchingImport, sequence uint64) error {
	seq, err := switchingSequence(sequence)
	if err != nil {
		return err
	}
	counts, err := json.Marshal(imp.Counts)
	if err != nil {
		return err
	}
	gaps, err := json.Marshal(imp.GapCounts)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO switching_imports (tenant_id, id, name, format, preview_digest, rows_total, counts, gap_counts, status,
		                               created_by, created_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'recording', $9, $10, $11)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID, imp.ID, imp.Name, imp.Format, imp.PreviewDigest, imp.RowsTotal, counts, gaps, imp.CreatedBy, imp.CreatedAt.UTC(), seq)
	return err
}

// ApplySwitchingImportRowsRecordedTx projects one batch of rows. A replayed
// batch adds nothing.
func (s *Store) ApplySwitchingImportRowsRecordedTx(ctx context.Context, tx pgx.Tx, tenantID, importID string, rows []SwitchingImportRow, sequence uint64) error {
	seq, err := switchingSequence(sequence)
	if err != nil {
		return err
	}
	batch, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO switching_import_rows (tenant_id, import_id, row_number, outcome, gaps, reason, duplicate_of, fingerprint,
		                                   common_name, sans, key_algorithm, serial, issuer, not_after, folder, profile, application,
		                                   owner_email, endpoints, certificate_der, event_sequence)
		SELECT $1, $2, r.row_number, r.outcome, coalesce(ARRAY(SELECT jsonb_array_elements_text(coalesce(r.gaps, '[]'::jsonb))), '{}'),
		       coalesce(r.reason, ''), r.duplicate_of, coalesce(r.fingerprint, ''), coalesce(r.common_name, ''),
		       coalesce(ARRAY(SELECT jsonb_array_elements_text(coalesce(r.sans, '[]'::jsonb))), '{}'), coalesce(r.key_algorithm, ''),
		       coalesce(r.serial, ''), coalesce(r.issuer, ''), r.not_after, coalesce(r.folder, ''), coalesce(r.profile, ''),
		       coalesce(r.application, ''), coalesce(r.owner_email, ''),
		       coalesce(ARRAY(SELECT jsonb_array_elements_text(coalesce(r.endpoints, '[]'::jsonb))), '{}'),
		       decode(nullif(r.certificate_der, ''), 'base64'), $4
		  FROM jsonb_to_recordset($3::jsonb) AS r(row_number integer, outcome text, gaps jsonb, reason text, duplicate_of integer,
		       fingerprint text, common_name text, sans jsonb, key_algorithm text, serial text, issuer text, not_after timestamptz,
		       folder text, profile text, application text, owner_email text, endpoints jsonb, certificate_der text)
		ON CONFLICT (tenant_id, import_id, row_number) DO NOTHING`, tenantID, importID, batch, seq)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE switching_imports SET rows_recorded = rows_recorded + $3, event_sequence = $4
		WHERE tenant_id = $1 AND id = $2`, tenantID, importID, tag.RowsAffected(), seq)
	return err
}

// ApplySwitchingImportRowsAppliedTx records what a batch of rows became. A row
// applied once is not applied again.
func (s *Store) ApplySwitchingImportRowsAppliedTx(ctx context.Context, tx pgx.Tx, tenantID, importID string, rows []SwitchingRowApplied, at time.Time, sequence uint64) error {
	seq, err := switchingSequence(sequence)
	if err != nil {
		return err
	}
	batch, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE switching_import_rows AS t
		   SET certificate_id = nullif(r.certificate_id, '')::uuid, owner_id = nullif(r.owner_id, '')::uuid,
		       linked = coalesce(r.linked, false), applied_at = $4, event_sequence = $5
		  FROM jsonb_to_recordset($3::jsonb) AS r(row_number integer, certificate_id text, owner_id text, linked boolean)
		 WHERE t.tenant_id = $1 AND t.import_id = $2 AND t.row_number = r.row_number AND t.applied_at IS NULL`,
		tenantID, importID, batch, at.UTC(), seq)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE switching_imports SET rows_applied = rows_applied + $3, event_sequence = $4
		WHERE tenant_id = $1 AND id = $2`, tenantID, importID, tag.RowsAffected(), seq)
	return err
}

// ApplySwitchingImportCompletedTx marks an import complete.
func (s *Store) ApplySwitchingImportCompletedTx(ctx context.Context, tx pgx.Tx, tenantID, importID string, at time.Time, sequence uint64) error {
	seq, err := switchingSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE switching_imports SET status = 'completed', completed_at = $3, event_sequence = $4
		WHERE tenant_id = $1 AND id = $2 AND status <> 'completed'`, tenantID, importID, at.UTC(), seq)
	return err
}

const switchingImportColumns = `id::text, name, format, preview_digest, rows_total, counts, gap_counts, rows_recorded, rows_applied,
	status, created_by, created_at, completed_at, watch_round, watch_pending, watch_allow_private, watch_private_cidrs,
	watch_requested_at, watch_requested_by`

func scanSwitchingImport(row pgx.Row) (SwitchingImport, error) {
	var imp SwitchingImport
	var counts, gaps []byte
	if err := row.Scan(&imp.ID, &imp.Name, &imp.Format, &imp.PreviewDigest, &imp.RowsTotal, &counts, &gaps, &imp.RowsRecorded,
		&imp.RowsApplied, &imp.Status, &imp.CreatedBy, &imp.CreatedAt, &imp.CompletedAt, &imp.WatchRound, &imp.WatchPending,
		&imp.WatchAllowPrivate, &imp.WatchPrivateCIDRs, &imp.WatchRequestedAt, &imp.WatchRequestedBy); err != nil {
		return imp, err
	}
	if err := json.Unmarshal(counts, &imp.Counts); err != nil {
		return imp, err
	}
	return imp, json.Unmarshal(gaps, &imp.GapCounts)
}

// GetSwitchingImport reads one import.
func (s *Store) GetSwitchingImport(ctx context.Context, tenantID, id string) (SwitchingImport, error) {
	var imp SwitchingImport
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		imp, err = scanSwitchingImport(tx.QueryRow(ctx, `SELECT `+switchingImportColumns+` FROM switching_imports
			WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SwitchingImport{}, ErrSwitchingImportNotFound
	}
	return imp, err
}

// ListSwitchingImports lists imports, newest first.
func (s *Store) ListSwitchingImports(ctx context.Context, tenantID string, limit int) ([]SwitchingImport, error) {
	out := []SwitchingImport{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+switchingImportColumns+` FROM switching_imports WHERE tenant_id = $1
			ORDER BY created_at DESC, id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			imp, err := scanSwitchingImport(rows)
			if err != nil {
				return err
			}
			out = append(out, imp)
		}
		return rows.Err()
	})
	return out, err
}

const switchingRowColumns = `row_number, outcome, gaps, reason, duplicate_of, fingerprint, common_name, sans, key_algorithm, serial,
	issuer, not_after, folder, profile, application, owner_email, endpoints, certificate_der, coalesce(certificate_id::text, ''),
	coalesce(owner_id::text, ''), linked, applied_at, watch_round, watch_status, watch_endpoint, served_fingerprint, watch_detail,
	watched_at`

func scanSwitchingRow(row pgx.Row) (SwitchingImportRow, error) {
	var r SwitchingImportRow
	err := row.Scan(&r.Row, &r.Outcome, &r.Gaps, &r.Reason, &r.DuplicateOf, &r.Fingerprint, &r.CommonName, &r.SANs, &r.KeyAlgorithm,
		&r.Serial, &r.Issuer, &r.NotAfter, &r.Folder, &r.Profile, &r.Application, &r.OwnerEmail, &r.Endpoints, &r.CertificateDER,
		&r.CertificateID, &r.OwnerID, &r.Linked, &r.AppliedAt, &r.WatchRound, &r.WatchStatus, &r.WatchEndpoint, &r.ServedFingerprint,
		&r.WatchDetail, &r.WatchedAt)
	return r, err
}

// ListSwitchingImportRows pages an import's rows in row order after afterRow,
// optionally only one outcome or one watch status.
func (s *Store) ListSwitchingImportRows(ctx context.Context, tenantID, importID, outcome, watchStatus string, afterRow, limit int) ([]SwitchingImportRow, error) {
	out := []SwitchingImportRow{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+switchingRowColumns+` FROM switching_import_rows
			WHERE tenant_id = $1 AND import_id = $2 AND ($3 = '' OR outcome = $3) AND ($4 = '' OR watch_status = $4) AND row_number > $5
			ORDER BY row_number LIMIT $6`, tenantID, importID, outcome, watchStatus, afterRow, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanSwitchingRow(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// PendingSwitchingImportRows lists up to limit mapped rows not applied yet.
func (s *Store) PendingSwitchingImportRows(ctx context.Context, tenantID, importID string, limit int) ([]SwitchingImportRow, error) {
	out := []SwitchingImportRow{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+switchingRowColumns+` FROM switching_import_rows
			WHERE tenant_id = $1 AND import_id = $2 AND applied_at IS NULL AND outcome IN ('mapped', 'mapped_with_gaps')
			ORDER BY row_number LIMIT $3`, tenantID, importID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanSwitchingRow(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// RecordingSwitchingImports lists up to limit of a tenant's imports still
// being applied, oldest first.
func (s *Store) RecordingSwitchingImports(ctx context.Context, tenantID string, limit int) ([]SwitchingImport, error) {
	out := []SwitchingImport{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+switchingImportColumns+` FROM switching_imports
			WHERE tenant_id = $1 AND status = 'recording' ORDER BY created_at, id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			imp, err := scanSwitchingImport(rows)
			if err != nil {
				return err
			}
			out = append(out, imp)
		}
		return rows.Err()
	})
	return out, err
}

// TenantsWithSwitchingWork lists up to 100 tenant IDs with an import still
// being applied, a watch round still running, or a watched import whose last
// round started before dueBefore.
func (s *Store) TenantsWithSwitchingWork(ctx context.Context, dueBefore time.Time) ([]string, error) {
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — cross-tenant by design: the leader's switching-import worker lists at most 100 tenant IDs with an import to apply or watch, then re-enters each tenant's RLS context for the import and its rows (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM switching_imports
		  WHERE status = 'recording' OR watch_pending > 0
		     OR (status = 'completed' AND watch_round > 0 AND watch_requested_at < $1)
		  ORDER BY 1 LIMIT 100`, dueBefore.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		out = append(out, tenantID)
	}
	return out, rows.Err()
}

// InventoryCertificate is a certificate already in a tenant's inventory.
type InventoryCertificate struct {
	ID     string
	Source string
}

// CertificatesByFingerprint reads which of fingerprints a tenant's inventory
// already has.
func (s *Store) CertificatesByFingerprint(ctx context.Context, tenantID string, fingerprints []string) (map[string]InventoryCertificate, error) {
	out := map[string]InventoryCertificate{}
	if len(fingerprints) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT fingerprint, id::text, source FROM certificates
			WHERE tenant_id = $1 AND fingerprint = ANY($2)`, tenantID, fingerprints)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var fp string
			var c InventoryCertificate
			if err := rows.Scan(&fp, &c.ID, &c.Source); err != nil {
				return err
			}
			out[fp] = c
		}
		return rows.Err()
	})
	return out, err
}

// ApplySwitchingWatchRequestedTx starts watch round round of an import: every
// mapped row is pending until the round observes it. A replayed or older
// round changes nothing.
func (s *Store) ApplySwitchingWatchRequestedTx(ctx context.Context, tx pgx.Tx, tenantID, importID string, round int, allowPrivate bool,
	cidrs []string, by string, at time.Time, sequence uint64) error {
	seq, err := switchingSequence(sequence)
	if err != nil {
		return err
	}
	if cidrs == nil {
		cidrs = []string{}
	}
	_, err = tx.Exec(ctx, `
		UPDATE switching_imports AS i
		   SET watch_round = $3, watch_allow_private = $4, watch_private_cidrs = $5, watch_requested_by = $6,
		       watch_requested_at = $7, event_sequence = $8,
		       watch_pending = (SELECT count(*) FROM switching_import_rows r
		                         WHERE r.tenant_id = i.tenant_id AND r.import_id = i.id
		                           AND r.outcome IN ('mapped', 'mapped_with_gaps') AND r.watch_round < $3)
		 WHERE i.tenant_id = $1 AND i.id = $2 AND i.watch_round < $3`,
		tenantID, importID, round, allowPrivate, cidrs, by, at.UTC(), seq)
	return err
}

// ApplySwitchingWatchObservedTx records one batch of a round's observations.
// A row already observed in this round keeps its first observation.
func (s *Store) ApplySwitchingWatchObservedTx(ctx context.Context, tx pgx.Tx, tenantID, importID string, round int,
	results []SwitchingWatchResult, at time.Time, sequence uint64) error {
	seq, err := switchingSequence(sequence)
	if err != nil {
		return err
	}
	batch, err := json.Marshal(results)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE switching_import_rows AS t
		   SET watch_round = $4, watch_status = r.status, watch_endpoint = coalesce(r.endpoint, ''),
		       served_fingerprint = coalesce(r.served_fingerprint, ''), watch_detail = coalesce(r.detail, ''), watched_at = $5,
		       event_sequence = $6
		  FROM jsonb_to_recordset($3::jsonb) AS r(row_number integer, status text, endpoint text, served_fingerprint text, detail text)
		 WHERE t.tenant_id = $1 AND t.import_id = $2 AND t.row_number = r.row_number AND t.watch_round < $4`,
		tenantID, importID, batch, round, at.UTC(), seq)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE switching_imports SET watch_pending = greatest(watch_pending - $4, 0), event_sequence = $5
		WHERE tenant_id = $1 AND id = $2 AND watch_round = $3`, tenantID, importID, round, tag.RowsAffected(), seq)
	return err
}

// PendingSwitchingWatchRows lists up to limit mapped rows a watch round has
// not observed yet.
func (s *Store) PendingSwitchingWatchRows(ctx context.Context, tenantID, importID string, round, limit int) ([]SwitchingImportRow, error) {
	out := []SwitchingImportRow{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+switchingRowColumns+` FROM switching_import_rows
			WHERE tenant_id = $1 AND import_id = $2 AND outcome IN ('mapped', 'mapped_with_gaps') AND watch_round < $3
			ORDER BY row_number LIMIT $4`, tenantID, importID, round, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanSwitchingRow(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// SwitchingImportsWithWatchWork lists up to limit of a tenant's imports with a
// watch round running, or watched and last started before dueBefore.
func (s *Store) SwitchingImportsWithWatchWork(ctx context.Context, tenantID string, dueBefore time.Time, limit int) ([]SwitchingImport, error) {
	out := []SwitchingImport{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+switchingImportColumns+` FROM switching_imports
			WHERE tenant_id = $1 AND (watch_pending > 0 OR (status = 'completed' AND watch_round > 0 AND watch_requested_at < $2))
			ORDER BY watch_requested_at, id LIMIT $3`, tenantID, dueBefore.UTC(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			imp, err := scanSwitchingImport(rows)
			if err != nil {
				return err
			}
			out = append(out, imp)
		}
		return rows.Err()
	})
	return out, err
}

// SwitchingWatchCounts counts an import's mapped rows by their last watch
// status (not_observed for a row no round has observed).
func (s *Store) SwitchingWatchCounts(ctx context.Context, tenantID, importID string) (map[string]int, error) {
	out := map[string]int{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT watch_status, count(*) FROM switching_import_rows
			WHERE tenant_id = $1 AND import_id = $2 AND outcome IN ('mapped', 'mapped_with_gaps') GROUP BY watch_status`, tenantID, importID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var status string
			var n int
			if err := rows.Scan(&status, &n); err != nil {
				return err
			}
			if status == "" {
				status = "not_observed"
			}
			out[status] = n
		}
		return rows.Err()
	})
	return out, err
}
