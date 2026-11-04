// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Renewal waves of a switching import (A265): the projections of
// switching.wave.cut_over and switching.wave.rolled_back. A wave row names the
// one identity trstctl keeps for an imported row; live is false once its wave
// is rolled back.

// ErrSwitchingWaveNotFound is a wave this tenant does not have.
var ErrSwitchingWaveNotFound = errors.New("store: switching wave not found")

// SwitchingWave is one renewal wave.
type SwitchingWave struct {
	ID             string
	ImportID       string
	Name           string
	Status         string
	IssuerID       string
	PreviewDigest  string
	RowsTotal      int
	CreatedBy      string
	CreatedAt      time.Time
	RolledBackAt   *time.Time
	RolledBackBy   string
	RollbackReason string
}

// SwitchingWaveRow is one row a wave moved to trstctl.
type SwitchingWaveRow struct {
	WaveID              string `json:"-"`
	ImportID            string `json:"-"`
	Row                 int    `json:"row_number"`
	IdentityID          string `json:"identity_id"`
	TargetID            string `json:"target_id"`
	ImportedFingerprint string `json:"imported_fingerprint"`
	Live                bool   `json:"-"`
}

// ApplySwitchingWaveCutOverTx projects a wave and its rows. A replay adds
// nothing.
func (s *Store) ApplySwitchingWaveCutOverTx(ctx context.Context, tx pgx.Tx, tenantID string, wave SwitchingWave, rows []SwitchingWaveRow,
	sequence uint64) error {
	seq, err := switchingSequence(sequence)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO switching_waves (tenant_id, id, import_id, name, status, issuer_id, preview_digest, rows_total,
		                             created_by, created_at, event_sequence)
		VALUES ($1, $2, $3, $4, 'cut_over', $5, $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID, wave.ID, wave.ImportID, wave.Name, wave.IssuerID, wave.PreviewDigest, len(rows), wave.CreatedBy,
		wave.CreatedAt.UTC(), seq)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	batch, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO switching_wave_rows (tenant_id, wave_id, import_id, row_number, identity_id, target_id, imported_fingerprint,
		                                 event_sequence)
		SELECT $1, $2, $3, r.row_number, r.identity_id::uuid, r.target_id::uuid, r.imported_fingerprint, $5
		  FROM jsonb_to_recordset($4::jsonb) AS r(row_number integer, identity_id text, target_id text, imported_fingerprint text)
		ON CONFLICT (tenant_id, wave_id, row_number) DO NOTHING`, tenantID, wave.ID, wave.ImportID, batch, seq)
	return err
}

// ApplySwitchingWaveRolledBackTx marks a wave rolled back and its rows no
// longer live.
func (s *Store) ApplySwitchingWaveRolledBackTx(ctx context.Context, tx pgx.Tx, tenantID, waveID, by, reason string, at time.Time,
	sequence uint64) error {
	seq, err := switchingSequence(sequence)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE switching_waves SET status = 'rolled_back', rolled_back_at = $3, rolled_back_by = $4,
		rollback_reason = $5, event_sequence = $6 WHERE tenant_id = $1 AND id = $2 AND status = 'cut_over'`,
		tenantID, waveID, at.UTC(), by, reason, seq)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE switching_wave_rows SET live = false, event_sequence = $3 WHERE tenant_id = $1 AND wave_id = $2`,
		tenantID, waveID, seq)
	return err
}

// IdentitiesWithIssuanceOrRenewalInFlight lists which of identityIDs have an
// issue or renewal job queued or running.
func (s *Store) IdentitiesWithIssuanceOrRenewalInFlight(ctx context.Context, tenantID string, identityIDs []string) ([]string, error) {
	out := []string{}
	if len(identityIDs) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT convert_from(payload, 'UTF8')::jsonb->>'identity_id' FROM outbox
			WHERE tenant_id = $1 AND status IN ('pending', 'processing') AND destination IN ('ca.issue', 'ca.renew', 'endpoint.renew')
			  AND convert_from(payload, 'UTF8')::jsonb->>'identity_id' = ANY($2) ORDER BY 1`, tenantID, identityIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out, err
}

const switchingWaveColumns = `id::text, import_id::text, name, status, issuer_id, preview_digest, rows_total,
	created_by, created_at, rolled_back_at, rolled_back_by, rollback_reason`

func scanSwitchingWave(row pgx.Row) (SwitchingWave, error) {
	var w SwitchingWave
	err := row.Scan(&w.ID, &w.ImportID, &w.Name, &w.Status, &w.IssuerID, &w.PreviewDigest, &w.RowsTotal, &w.CreatedBy,
		&w.CreatedAt, &w.RolledBackAt, &w.RolledBackBy, &w.RollbackReason)
	return w, err
}

// GetSwitchingWave reads one wave.
func (s *Store) GetSwitchingWave(ctx context.Context, tenantID, id string) (SwitchingWave, error) {
	var w SwitchingWave
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		w, err = scanSwitchingWave(tx.QueryRow(ctx, `SELECT `+switchingWaveColumns+` FROM switching_waves
			WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SwitchingWave{}, ErrSwitchingWaveNotFound
	}
	return w, err
}

// ListSwitchingWaves lists an import's waves, newest first.
func (s *Store) ListSwitchingWaves(ctx context.Context, tenantID, importID string) ([]SwitchingWave, error) {
	out := []SwitchingWave{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+switchingWaveColumns+` FROM switching_waves
			WHERE tenant_id = $1 AND import_id = $2 ORDER BY created_at DESC, id`, tenantID, importID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			w, err := scanSwitchingWave(rows)
			if err != nil {
				return err
			}
			out = append(out, w)
		}
		return rows.Err()
	})
	return out, err
}

// ListSwitchingWaveRows lists a wave's rows in row order.
func (s *Store) ListSwitchingWaveRows(ctx context.Context, tenantID, waveID string) ([]SwitchingWaveRow, error) {
	out := []SwitchingWaveRow{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT wave_id::text, import_id::text, row_number, identity_id::text, target_id::text, imported_fingerprint, live
			FROM switching_wave_rows WHERE tenant_id = $1 AND wave_id = $2 ORDER BY row_number`, tenantID, waveID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r SwitchingWaveRow
			if err := rows.Scan(&r.WaveID, &r.ImportID, &r.Row, &r.IdentityID, &r.TargetID, &r.ImportedFingerprint, &r.Live); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// LiveSwitchingWaveRows maps an import's rows in a live wave to that wave row.
func (s *Store) LiveSwitchingWaveRows(ctx context.Context, tenantID, importID string) (map[int]SwitchingWaveRow, error) {
	out := map[int]SwitchingWaveRow{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT wave_id::text, import_id::text, row_number, identity_id::text, target_id::text, imported_fingerprint, live
			FROM switching_wave_rows WHERE tenant_id = $1 AND import_id = $2 AND live`, tenantID, importID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r SwitchingWaveRow
			if err := rows.Scan(&r.WaveID, &r.ImportID, &r.Row, &r.IdentityID, &r.TargetID, &r.ImportedFingerprint, &r.Live); err != nil {
				return err
			}
			out[r.Row] = r
		}
		return rows.Err()
	})
	return out, err
}

// TrstctlFingerprintsForIdentities maps each identity to the fingerprints of
// the certificates trstctl issued for it.
func (s *Store) TrstctlFingerprintsForIdentities(ctx context.Context, tenantID string, identityIDs []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(identityIDs) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT i.id::text, c.fingerprint
			  FROM identities i
			  JOIN certificates c ON c.tenant_id = i.tenant_id AND c.owner_id = i.owner_id AND i.name = ANY(c.sans)
			 WHERE i.tenant_id = $1 AND i.id::text = ANY($2) AND (c.source = 'issued' OR c.issuance_idempotency_key <> '')`,
			tenantID, identityIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, fp string
			if err := rows.Scan(&id, &fp); err != nil {
				return err
			}
			out[id] = append(out[id], fp)
		}
		return rows.Err()
	})
	return out, err
}

// SwitchingImportRowsForWave reads the rows a wave request selects: the
// numbered rows, or every row in a folder, application group or owner's
// email (any of them given), in row order, at most limit.
func (s *Store) SwitchingImportRowsForWave(ctx context.Context, tenantID, importID string, numbers []int, folder, application,
	ownerEmail string, limit int) ([]SwitchingImportRow, error) {
	out := []SwitchingImportRow{}
	if numbers == nil {
		numbers = []int{}
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+switchingRowColumns+` FROM switching_import_rows
			WHERE tenant_id = $1 AND import_id = $2
			  AND (cardinality($3::int[]) = 0 OR row_number = ANY($3::int[]))
			  AND ($4 = '' OR folder = $4) AND ($5 = '' OR application = $5) AND ($6 = '' OR lower(owner_email) = lower($6))
			ORDER BY row_number LIMIT $7`, tenantID, importID, numbers, folder, application, ownerEmail, limit)
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

// OtherActiveIdentitiesOnTarget lists the active identities bound to a
// deployment target other than identityID: a target carries one.
func (s *Store) OtherActiveIdentitiesOnTarget(ctx context.Context, tenantID, targetID, identityID string) ([]string, error) {
	out := []string{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text FROM identities
			WHERE tenant_id = $1 AND attributes->>'deployment_target_id' = $2 AND id::text <> $3
			  AND status NOT IN ('revoked', 'retired') ORDER BY id`, tenantID, targetID, identityID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out, err
}
