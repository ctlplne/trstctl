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

// DiscoveryFindingSecretMove is a leaked-secret finding moved into the native
// secret store (P6): the secret's name and the version that holds the moved
// value, the history commits that still held it (locations only), and the
// first read of a newer version — a consumer picked up the rotated value. A
// later completed scan of the repository re-checks the residue (P6-L5):
// ResidueCheckedAt and ResidueRunID name the run that last looked, nil and ""
// until one has. A projection of discovery.finding.secret_moved,
// discovery.finding.secret_consumer_read and
// discovery.finding.secret_residue_checked; no value is ever kept.
type DiscoveryFindingSecretMove struct {
	TenantID            string
	FindingID           string
	SecretName          string
	SecretVersion       int
	MovedBy             string
	MovedAt             time.Time
	Residue             []SecretResidueLocation
	ConsumerReadVersion int
	ConsumerReader      string
	ConsumerReadAt      *time.Time
	ResidueCheckedAt    *time.Time
	ResidueRunID        string
}

// SecretResidueLocation is a history commit that held a moved value.
type SecretResidueLocation struct {
	RuleID string `json:"rule_id"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Commit string `json:"commit"`
}

// OpenSecretMove is a moved finding the leader has not closed, with what the
// closure needs from the finding: its source and the latest run that saw it.
type OpenSecretMove struct {
	DiscoveryFindingSecretMove
	SourceID     string
	RunID        string
	TriageStatus string
}

// secretMoveOpen is the triage states a moved finding can still be closed
// from: never triaged, unmanaged, under investigation or an accepted risk.
const secretMoveOpen = `f.triage_status NOT IN ('remediated', 'dismissed', 'managed')` // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)

// secretMoveColumns is the move columns every read selects.
const secretMoveColumns = /* #nosec G101 -- SQL column list, no credential (CWE-798) */ `m.finding_id::text, m.secret_name, m.secret_version, m.moved_by, m.moved_at, m.residue,
	       m.consumer_read_version, m.consumer_reader, m.consumer_read_at, m.residue_checked_at, coalesce(m.residue_run_id::text, '')`

func scanSecretMove(row pgx.Row, m *DiscoveryFindingSecretMove, extra ...any) error {
	var residue []byte
	var readVersion *int
	dest := append([]any{&m.FindingID, &m.SecretName, &m.SecretVersion, &m.MovedBy, &m.MovedAt, &residue,
		&readVersion, &m.ConsumerReader, &m.ConsumerReadAt, &m.ResidueCheckedAt, &m.ResidueRunID}, extra...)
	if err := row.Scan(dest...); err != nil {
		return err
	}
	if readVersion != nil {
		m.ConsumerReadVersion = *readVersion
	}
	if err := json.Unmarshal(residue, &m.Residue); err != nil {
		return fmt.Errorf("store: decode secret move residue: %w", err)
	}
	return nil
}

// ApplyDiscoveryFindingSecretMovedTx projects one move. A later event for the
// same finding replaces it (and forgets any consumer read of the old secret
// and any re-check of the old residue).
func (s *Store) ApplyDiscoveryFindingSecretMovedTx(ctx context.Context, tx pgx.Tx, m DiscoveryFindingSecretMove, sequence uint64) error {
	if m.TenantID == "" || m.FindingID == "" || m.SecretName == "" || m.SecretVersion < 1 || m.MovedAt.IsZero() {
		return errors.New("store: leaked-secret move is incomplete")
	}
	if sequence == 0 || sequence > uint64(1<<63-1) {
		return errors.New("store: leaked-secret move requires a positive int64 event sequence")
	}
	residue := m.Residue
	if residue == nil {
		residue = []SecretResidueLocation{}
	}
	encoded, err := json.Marshal(residue)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO discovery_finding_secret_moves
		       (tenant_id, finding_id, secret_name, secret_version, moved_by, moved_at, residue, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, finding_id) DO UPDATE
		   SET secret_name = EXCLUDED.secret_name, secret_version = EXCLUDED.secret_version,
		       moved_by = EXCLUDED.moved_by, moved_at = EXCLUDED.moved_at, residue = EXCLUDED.residue,
		       consumer_read_version = NULL, consumer_reader = '', consumer_read_at = NULL,
		       residue_checked_at = NULL, residue_run_id = NULL,
		       event_sequence = EXCLUDED.event_sequence
		 WHERE discovery_finding_secret_moves.event_sequence < EXCLUDED.event_sequence`,
		m.TenantID, m.FindingID, m.SecretName, m.SecretVersion, m.MovedBy, m.MovedAt.UTC(), encoded, int64(sequence)) // #nosec G115 -- bounded to int64 above (CWE-190)
	return err
}

// ApplyDiscoveryFindingSecretConsumerReadTx projects the first read of a
// version newer than the moved one. Later reads change nothing.
func (s *Store) ApplyDiscoveryFindingSecretConsumerReadTx(ctx context.Context, tx pgx.Tx, tenantID, findingID string, version int, reader string, at time.Time, sequence uint64) error {
	if sequence == 0 || sequence > uint64(1<<63-1) {
		return errors.New("store: a moved secret's consumer read requires a positive int64 event sequence")
	}
	_, err := tx.Exec(ctx, `
		UPDATE discovery_finding_secret_moves
		   SET consumer_read_version = $3, consumer_reader = $4, consumer_read_at = $5,
		       event_sequence = GREATEST(event_sequence, $6)
		 WHERE tenant_id = $1 AND finding_id = $2 AND consumer_read_at IS NULL AND secret_version < $3`,
		tenantID, findingID, version, reader, at.UTC(), int64(sequence)) // #nosec G115 -- bounded to int64 above (CWE-190)
	return err
}

// ApplyDiscoveryFindingSecretResidueCheckedTx projects a re-check of a moved
// secret's history residue (P6-L5): the residue the scan run found replaces
// the recorded one. A check of another move of the finding (another secret or
// version) or one older than the last applied changes nothing.
func (s *Store) ApplyDiscoveryFindingSecretResidueCheckedTx(ctx context.Context, tx pgx.Tx, tenantID, findingID, secretName string,
	secretVersion int, runID string, residue []SecretResidueLocation, checkedAt time.Time, sequence uint64) error {
	if tenantID == "" || findingID == "" || secretName == "" || secretVersion < 1 || runID == "" || checkedAt.IsZero() {
		return errors.New("store: a moved secret's residue check is incomplete")
	}
	if len(residue) > 100 {
		return errors.New("store: a moved secret's residue holds at most 100 locations")
	}
	if sequence == 0 || sequence > uint64(1<<63-1) {
		return errors.New("store: a moved secret's residue check requires a positive int64 event sequence")
	}
	if residue == nil {
		residue = []SecretResidueLocation{}
	}
	encoded, err := json.Marshal(residue)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE discovery_finding_secret_moves
		   SET residue = $6, residue_checked_at = $7, residue_run_id = $5::uuid,
		       event_sequence = GREATEST(event_sequence, $8)
		 WHERE tenant_id = $1 AND finding_id = $2 AND secret_name = $3 AND secret_version = $4
		   AND (residue_checked_at IS NULL OR residue_checked_at <= $7)`,
		tenantID, findingID, secretName, secretVersion, runID, encoded, checkedAt.UTC(), int64(sequence)) // #nosec G115 -- bounded to int64 above (CWE-190)
	return err
}

// SecretMovesForSource returns up to limit of the moves of a source's
// findings, open or closed, for a scan of that source to re-check their
// history residue (P6-L5).
func (s *Store) SecretMovesForSource(ctx context.Context, tenantID, sourceID string, limit int) ([]DiscoveryFindingSecretMove, error) {
	if limit <= 0 {
		return nil, errors.New("store: SecretMovesForSource requires a positive limit")
	}
	var out []DiscoveryFindingSecretMove
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+secretMoveColumns+`
			  FROM discovery_finding_secret_moves m
			  JOIN discovery_findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
			 WHERE m.tenant_id = $1 AND f.source_id::text = $2
			 ORDER BY m.finding_id LIMIT $3`, tenantID, sourceID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			m := DiscoveryFindingSecretMove{TenantID: tenantID}
			if err := scanSecretMove(rows, &m); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// DiscoveryFindingSecretMovesFor returns the moves of the named findings.
func (s *Store) DiscoveryFindingSecretMovesFor(ctx context.Context, tenantID string, findingIDs []string) (map[string]DiscoveryFindingSecretMove, error) {
	out := map[string]DiscoveryFindingSecretMove{}
	if len(findingIDs) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+secretMoveColumns+`
			  FROM discovery_finding_secret_moves m
			 WHERE m.tenant_id = $1 AND m.finding_id::text = ANY($2)`, tenantID, findingIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			m := DiscoveryFindingSecretMove{TenantID: tenantID}
			if err := scanSecretMove(rows, &m); err != nil {
				return err
			}
			out[m.FindingID] = m
		}
		return rows.Err()
	})
	return out, err
}

// GetDiscoveryFindingSecretMove returns one finding's move, if it moved.
func (s *Store) GetDiscoveryFindingSecretMove(ctx context.Context, tenantID, findingID string) (DiscoveryFindingSecretMove, bool, error) {
	moves, err := s.DiscoveryFindingSecretMovesFor(ctx, tenantID, []string{findingID})
	if err != nil {
		return DiscoveryFindingSecretMove{}, false, err
	}
	m, ok := moves[findingID]
	return m, ok, nil
}

// MovedFindingsAwaitingConsumerRead lists the open findings moved into
// secretName at a version older than version that no consumer has yet read
// a newer version of.
func (s *Store) MovedFindingsAwaitingConsumerRead(ctx context.Context, tenantID, secretName string, version, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, errors.New("store: MovedFindingsAwaitingConsumerRead requires a positive limit")
	}
	var out []string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT m.finding_id::text
			  FROM discovery_finding_secret_moves m
			  JOIN discovery_findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
			 WHERE m.tenant_id = $1 AND m.secret_name = $2 AND m.consumer_read_at IS NULL
			   AND m.secret_version < $3 AND `+secretMoveOpen+`
			 ORDER BY m.finding_id LIMIT $4`, tenantID, secretName, version, limit)
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

// TenantsWithOpenSecretMoves lists the tenants holding a moved finding that
// is not closed, for the leader's closure worker.
func (s *Store) TenantsWithOpenSecretMoves(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants hold an open moved leaked-secret finding so the leader-only closure worker can visit each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT m.tenant_id::text
		   FROM discovery_finding_secret_moves m
		   JOIN discovery_findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
		  WHERE `+secretMoveOpen+` ORDER BY 1`)
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

// OpenSecretMoves returns up to limit of a tenant's moved findings that are
// not closed, with each finding's source and the latest run that saw it.
func (s *Store) OpenSecretMoves(ctx context.Context, tenantID string, limit int) ([]OpenSecretMove, error) {
	if limit <= 0 {
		return nil, errors.New("store: OpenSecretMoves requires a positive limit")
	}
	var out []OpenSecretMove
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+secretMoveColumns+`,
			       coalesce(f.source_id::text, ''), coalesce(f.run_id::text, ''), f.triage_status
			  FROM discovery_finding_secret_moves m
			  JOIN discovery_findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
			 WHERE m.tenant_id = $1 AND `+secretMoveOpen+`
			 ORDER BY m.finding_id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			m := OpenSecretMove{DiscoveryFindingSecretMove: DiscoveryFindingSecretMove{TenantID: tenantID}}
			if err := scanSecretMove(rows, &m.DiscoveryFindingSecretMove, &m.SourceID, &m.RunID, &m.TriageStatus); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// LatestCompletedDiscoveryRunAfter returns the newest run of a source that
// completed (succeeded or partial) after a time. A failed run is never
// evidence of anything, so it is never returned.
func (s *Store) LatestCompletedDiscoveryRunAfter(ctx context.Context, tenantID, sourceID string, after time.Time) (string, time.Time, bool, error) {
	var (
		id    string
		at    time.Time
		found bool
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT id::text, completed_at FROM discovery_runs
			 WHERE tenant_id = $1 AND source_id = $2 AND status IN ('succeeded', 'partial')
			   AND completed_at > $3
			 ORDER BY completed_at DESC, id DESC LIMIT 1`, tenantID, sourceID, after.UTC()).Scan(&id, &at)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	return id, at, found, err
}
