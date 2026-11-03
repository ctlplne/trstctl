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

// Secret migrations (A243): a run's value-free plan, the objects it wrote with
// the versions it found (the rollback manifest), who writes each secret now,
// and its consumers' first reads. A projection of the secret.migration.*
// events; no value is kept.

// Run states.
const (
	SecretMigrationAssessed   = "assessed"
	SecretMigrationStaged     = "staged"
	SecretMigrationCutOver    = "cut-over"
	SecretMigrationRolledBack = "rolled-back"
)

// Object outcomes, writers and rollback results.
const (
	SecretMigrationMigrated = "migrated"
	SecretMigrationReissued = "reissued"

	SecretMigrationWriterSource = "source"
	SecretMigrationWriterStore  = "store"

	SecretMigrationRollbackRestored = "restored"
	SecretMigrationRollbackDeleted  = "deleted"
	SecretMigrationRollbackKept     = "kept"
)

// SecretMigration is one run.
type SecretMigration struct {
	TenantID           string
	ID                 string
	Project            string
	State              string
	Digest             string
	Plan               json.RawMessage
	AcceptedOpen       []string
	CreatedBy          string
	CreatedAt          time.Time
	StagedAt           *time.Time
	StagedBy           string
	PermissionsApplied json.RawMessage
	CutOverAt          *time.Time
	CutOverBy          string
	RolledBackAt       *time.Time
	RolledBackBy       string
	UpdatedAt          time.Time
	Objects            []SecretMigrationObject
	ConsumerReads      []SecretMigrationConsumerRead
}

// SecretMigrationObject is one object a run wrote.
type SecretMigrationObject struct {
	Name            string
	Outcome         string
	PriorVersion    int
	Version         int
	Writer          string
	Rollback        string
	RollbackVersion int
}

// SecretMigrationConsumerRead is a consumer's first read of a migrated secret.
type SecretMigrationConsumerRead struct {
	MigrationID string
	Consumer    string
	Name        string
	Version     int
	Reader      string
	ReadAt      time.Time
}

// ApplySecretMigrationAssessedTx records a run's assessment. A run already
// staged keeps its state and its rollback manifest; its plan and digest move
// to the new assessment (the export's system changed values it still writes).
func (s *Store) ApplySecretMigrationAssessedTx(ctx context.Context, tx pgx.Tx, m SecretMigration, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	if m.ID == "" || m.Project == "" || len(m.Digest) != 64 || len(m.Plan) == 0 || m.CreatedAt.IsZero() {
		return errors.New("store: a secret migration assessment is incomplete")
	}
	open, err := json.Marshal(nonNilStrings(m.AcceptedOpen))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO secret_migrations (tenant_id, id, project, state, digest, plan, accepted_open, created_by, created_at,
		                               updated_at, event_sequence)
		VALUES ($1, $2, $3, 'assessed', $4, $5, $6, $7, $8, $8, $9)
		ON CONFLICT (tenant_id, id) DO UPDATE
		   SET digest = excluded.digest, plan = excluded.plan, accepted_open = excluded.accepted_open,
		       updated_at = excluded.updated_at, event_sequence = excluded.event_sequence
		 WHERE secret_migrations.event_sequence < excluded.event_sequence
		   AND secret_migrations.state IN ('assessed', 'staged')`,
		m.TenantID, m.ID, m.Project, m.Digest, []byte(m.Plan), open, m.CreatedBy, m.CreatedAt.UTC(), seq)
	return err
}

// ApplySecretMigrationWrittenTx records versions a run wrote. A staged
// (migrated) object keeps the version it first found, so a re-stage never
// moves the rollback manifest; it is written by the export's system until
// cutover. A reissued object is the store's from the start.
func (s *Store) ApplySecretMigrationWrittenTx(ctx context.Context, tx pgx.Tx, tenantID, id, outcome string, items []SecretMigrationObject, by string, at time.Time, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	if id == "" || len(items) == 0 || at.IsZero() || (outcome != SecretMigrationMigrated && outcome != SecretMigrationReissued) {
		return errors.New("store: a secret migration write is incomplete")
	}
	writer := SecretMigrationWriterSource
	if outcome == SecretMigrationReissued {
		writer = SecretMigrationWriterStore
	}
	for _, item := range items {
		if item.Name == "" || item.Version < 1 || item.PriorVersion < 0 {
			return fmt.Errorf("store: secret migration object %q is incomplete", item.Name)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO secret_migration_objects (tenant_id, migration_id, name, outcome, prior_version, version, writer, event_sequence)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (tenant_id, migration_id, name) DO UPDATE
			   SET version = excluded.version, event_sequence = excluded.event_sequence
			 WHERE secret_migration_objects.event_sequence < excluded.event_sequence`,
			tenantID, id, item.Name, outcome, item.PriorVersion, item.Version, writer, seq); err != nil {
			return err
		}
	}
	if outcome != SecretMigrationMigrated {
		_, err = tx.Exec(ctx, `UPDATE secret_migrations SET updated_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at.UTC())
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE secret_migrations
		   SET state = 'staged', staged_at = coalesce(staged_at, $3), staged_by = $4, updated_at = $3
		 WHERE tenant_id = $1 AND id = $2 AND state IN ('assessed', 'staged')`, tenantID, id, at.UTC(), by)
	return err
}

// ApplySecretMigrationPermissionsAppliedTx records the grants a run applied.
func (s *Store) ApplySecretMigrationPermissionsAppliedTx(ctx context.Context, tx pgx.Tx, tenantID, id string, grants json.RawMessage, at time.Time, sequence uint64) error {
	if _, err := secretProjectSequence(sequence); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		UPDATE secret_migrations SET permissions_applied = permissions_applied || $3::jsonb, updated_at = $4
		 WHERE tenant_id = $1 AND id = $2`, tenantID, id, []byte(grants), at.UTC())
	return err
}

// ApplySecretMigrationConsumerReadTx records a consumer's first read.
func (s *Store) ApplySecretMigrationConsumerReadTx(ctx context.Context, tx pgx.Tx, tenantID string, r SecretMigrationConsumerRead, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	if r.MigrationID == "" || r.Consumer == "" || r.Name == "" || r.Version < 1 || r.Reader == "" || r.ReadAt.IsZero() {
		return errors.New("store: a secret migration consumer read is incomplete")
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO secret_migration_consumer_reads (tenant_id, migration_id, consumer, name, version, reader, read_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, migration_id, consumer, name) DO NOTHING`,
		tenantID, r.MigrationID, r.Consumer, r.Name, r.Version, r.Reader, r.ReadAt.UTC(), seq)
	return err
}

// ApplySecretMigrationCutOverTx hands each staged object's writing to the
// store.
func (s *Store) ApplySecretMigrationCutOverTx(ctx context.Context, tx pgx.Tx, tenantID, id, by string, at time.Time, sequence uint64) error {
	if _, err := secretProjectSequence(sequence); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE secret_migrations SET state = 'cut-over', cut_over_at = $3, cut_over_by = $4, updated_at = $3
		 WHERE tenant_id = $1 AND id = $2 AND state = 'staged'`, tenantID, id, at.UTC(), by); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		UPDATE secret_migration_objects SET writer = 'store'
		 WHERE tenant_id = $1 AND migration_id = $2 AND outcome = 'migrated'`, tenantID, id)
	return err
}

// ApplySecretMigrationRolledBackTx records a run's rollback, object by object.
func (s *Store) ApplySecretMigrationRolledBackTx(ctx context.Context, tx pgx.Tx, tenantID, id string, items []SecretMigrationObject, by string, at time.Time, sequence uint64) error {
	if _, err := secretProjectSequence(sequence); err != nil {
		return err
	}
	for _, item := range items {
		switch item.Rollback {
		case SecretMigrationRollbackRestored, SecretMigrationRollbackDeleted, SecretMigrationRollbackKept:
		default:
			return fmt.Errorf("store: unknown rollback %q", item.Rollback)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE secret_migration_objects SET rollback = $4, rollback_version = $5, writer = 'store'
			 WHERE tenant_id = $1 AND migration_id = $2 AND name = $3`,
			tenantID, id, item.Name, item.Rollback, item.RollbackVersion); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `
		UPDATE secret_migrations SET state = 'rolled-back', rolled_back_at = $3, rolled_back_by = $4, updated_at = $3
		 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at.UTC(), by)
	return err
}

const secretMigrationColumns = /* #nosec G101 -- SQL column list, no credential (CWE-798) */ `id::text, project, state, digest, plan, accepted_open, created_by, created_at, staged_at, staged_by,
	permissions_applied, cut_over_at, cut_over_by, rolled_back_at, rolled_back_by, updated_at`

func scanSecretMigration(row pgx.Row, m *SecretMigration) error {
	var open []byte
	if err := row.Scan(&m.ID, &m.Project, &m.State, &m.Digest, &m.Plan, &open, &m.CreatedBy, &m.CreatedAt, &m.StagedAt,
		&m.StagedBy, &m.PermissionsApplied, &m.CutOverAt, &m.CutOverBy, &m.RolledBackAt, &m.RolledBackBy, &m.UpdatedAt); err != nil {
		return err
	}
	return json.Unmarshal(open, &m.AcceptedOpen)
}

// GetSecretMigration returns one run with its objects and consumer reads.
func (s *Store) GetSecretMigration(ctx context.Context, tenantID, id string) (SecretMigration, error) {
	m := SecretMigration{TenantID: tenantID}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := scanSecretMigration(tx.QueryRow(ctx,
			`SELECT `+secretMigrationColumns+` FROM secret_migrations WHERE tenant_id = $1 AND id = $2`, tenantID, id), &m); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT name, outcome, prior_version, version, writer, rollback, rollback_version
			  FROM secret_migration_objects WHERE tenant_id = $1 AND migration_id = $2 ORDER BY name`, tenantID, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o SecretMigrationObject
			if err := rows.Scan(&o.Name, &o.Outcome, &o.PriorVersion, &o.Version, &o.Writer, &o.Rollback, &o.RollbackVersion); err != nil {
				return err
			}
			m.Objects = append(m.Objects, o)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		reads, err := tx.Query(ctx, `
			SELECT consumer, name, version, reader, read_at
			  FROM secret_migration_consumer_reads WHERE tenant_id = $1 AND migration_id = $2 ORDER BY consumer, name`, tenantID, id)
		if err != nil {
			return err
		}
		defer reads.Close()
		for reads.Next() {
			r := SecretMigrationConsumerRead{MigrationID: id}
			if err := reads.Scan(&r.Consumer, &r.Name, &r.Version, &r.Reader, &r.ReadAt); err != nil {
				return err
			}
			m.ConsumerReads = append(m.ConsumerReads, r)
		}
		return reads.Err()
	})
	if err != nil {
		// pgx.ErrNoRows reads as IsNotFound.
		return SecretMigration{}, err
	}
	return m, nil
}

// ListSecretMigrations lists a tenant's runs, newest first, without objects.
func (s *Store) ListSecretMigrations(ctx context.Context, tenantID string, limit int) ([]SecretMigration, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	var out []SecretMigration
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+secretMigrationColumns+` FROM secret_migrations
			WHERE tenant_id = $1 ORDER BY created_at DESC, id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			m := SecretMigration{TenantID: tenantID}
			if err := scanSecretMigration(rows, &m); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// SecretMigrationSourceWriter returns the run whose export's system writes
// name until cutover, or "" when the store does.
func (s *Store) SecretMigrationSourceWriter(ctx context.Context, tenantID, name string) (string, error) {
	var id string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT o.migration_id::text FROM secret_migration_objects o
			  JOIN secret_migrations m ON m.tenant_id = o.tenant_id AND m.id = o.migration_id
			 WHERE o.tenant_id = $1 AND o.name = $2 AND o.writer = 'source' AND o.rollback = '' AND m.state = 'staged'
			 LIMIT 1`, tenantID, name).Scan(&id)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// SecretMigrationsAwaitingConsumerRead returns, for a read of name by reader,
// each staged run and consumer that expects that read and has not recorded
// it.
func (s *Store) SecretMigrationsAwaitingConsumerRead(ctx context.Context, tenantID, name, reader string) ([][2]string, error) {
	var out [][2]string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT m.id::text, c->>'name'
			  FROM secret_migrations m, jsonb_array_elements(m.plan->'consumers') AS c
			 WHERE m.tenant_id = $1 AND m.state = 'staged'
			   AND c->>'subject' = $3 AND coalesce(c->>'problem', '') = ''
			   AND c->'secrets' ? $2
			   AND NOT EXISTS (SELECT 1 FROM secret_migration_consumer_reads r
			                    WHERE r.tenant_id = m.tenant_id AND r.migration_id = m.id
			                      AND r.consumer = c->>'name' AND r.name = $2)
			 LIMIT 20`, tenantID, name, reader)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var pair [2]string
			if err := rows.Scan(&pair[0], &pair[1]); err != nil {
				return err
			}
			out = append(out, pair)
		}
		return rows.Err()
	})
	return out, err
}
