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

// Rehearsals of failure scenarios (A247): a saved scenario and its runs, the
// projections of rehearsal.scenario.saved, rehearsal.run.started and
// rehearsal.run.completed. Candidate, data set, steps, expected effects and
// observations are stored as the events carry them (JSON); this package
// reads and writes them without interpreting them.

// ErrRehearsalNotFound is a scenario or run this tenant does not have.
var ErrRehearsalNotFound = errors.New("store: rehearsal not found")

// RehearsalScenario is one saved scenario at its latest revision.
type RehearsalScenario struct {
	ID        string
	Name      string
	Kind      string
	Revision  int64
	Candidate json.RawMessage
	DataSet   json.RawMessage
	Steps     json.RawMessage
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RehearsalRun is one replay of a scenario in one mode.
type RehearsalRun struct {
	ID                string
	ScenarioID        string
	ScenarioRevision  int64
	Mode              string
	Status            string
	Verdict           string
	Label             string
	ToolVersion       string
	ConnectorVersions json.RawMessage
	Candidate         json.RawMessage
	DataSetDigest     string
	Expected          json.RawMessage
	Observations      json.RawMessage
	Detail            string
	StartedBy         string
	StartedAt         time.Time
	CompletedAt       *time.Time
}

func rehearsalSequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > math.MaxInt64 {
		return 0, fmt.Errorf("store: rehearsal event sequence %d is out of range", sequence)
	}
	return int64(sequence), nil // #nosec G115 -- bounded above (CWE-190)
}

// ApplyRehearsalScenarioSavedTx projects a saved scenario. A later revision
// replaces an earlier one; a replayed or older event changes nothing.
func (s *Store) ApplyRehearsalScenarioSavedTx(ctx context.Context, tx pgx.Tx, tenantID string, sc RehearsalScenario, sequence uint64) error {
	seq, err := rehearsalSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO rehearsal_scenarios
		  (tenant_id, id, name, kind, revision, candidate, data_set, steps, created_by, created_at, updated_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11)
		ON CONFLICT (tenant_id, id) DO UPDATE SET
		  name = EXCLUDED.name, kind = EXCLUDED.kind, revision = EXCLUDED.revision,
		  candidate = EXCLUDED.candidate, data_set = EXCLUDED.data_set, steps = EXCLUDED.steps,
		  updated_at = EXCLUDED.updated_at, event_sequence = EXCLUDED.event_sequence
		WHERE rehearsal_scenarios.tenant_id = EXCLUDED.tenant_id AND rehearsal_scenarios.revision < EXCLUDED.revision`,
		tenantID, sc.ID, sc.Name, sc.Kind, sc.Revision, []byte(sc.Candidate), []byte(sc.DataSet), []byte(sc.Steps),
		sc.CreatedBy, sc.CreatedAt.UTC(), seq)
	return err
}

// ApplyRehearsalRunStartedTx projects a started run.
func (s *Store) ApplyRehearsalRunStartedTx(ctx context.Context, tx pgx.Tx, tenantID string, r RehearsalRun, sequence uint64) error {
	seq, err := rehearsalSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO rehearsal_runs
		  (tenant_id, id, scenario_id, scenario_revision, mode, status, tool_version, connector_versions,
		   candidate, data_set_digest, expected, started_by, started_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, 'running', $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID, r.ID, r.ScenarioID, r.ScenarioRevision, r.Mode, r.ToolVersion, []byte(r.ConnectorVersions),
		[]byte(r.Candidate), r.DataSetDigest, []byte(r.Expected), r.StartedBy, r.StartedAt.UTC(), seq)
	return err
}

// ApplyRehearsalRunCompletedTx records a run's observations, verdict and
// label. A run completes once.
func (s *Store) ApplyRehearsalRunCompletedTx(ctx context.Context, tx pgx.Tx, tenantID string, r RehearsalRun, sequence uint64) error {
	seq, err := rehearsalSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE rehearsal_runs SET status = 'completed', verdict = $3, label = $4, observations = $5,
		       detail = $6, completed_at = $7, event_sequence = $8
		 WHERE tenant_id = $1 AND id = $2 AND status = 'running'`,
		tenantID, r.ID, r.Verdict, r.Label, []byte(r.Observations), r.Detail, r.CompletedAt, seq)
	return err
}

const rehearsalScenarioColumns = `id::text, name, kind, revision, candidate, data_set, steps, created_by, created_at, updated_at`

func scanRehearsalScenario(row pgx.Row) (RehearsalScenario, error) {
	var sc RehearsalScenario
	err := row.Scan(&sc.ID, &sc.Name, &sc.Kind, &sc.Revision, &sc.Candidate, &sc.DataSet, &sc.Steps,
		&sc.CreatedBy, &sc.CreatedAt, &sc.UpdatedAt)
	return sc, err
}

// GetRehearsalScenario reads one scenario.
func (s *Store) GetRehearsalScenario(ctx context.Context, tenantID, id string) (RehearsalScenario, error) {
	var sc RehearsalScenario
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		sc, err = scanRehearsalScenario(tx.QueryRow(ctx,
			`SELECT `+rehearsalScenarioColumns+` FROM rehearsal_scenarios WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RehearsalScenario{}, ErrRehearsalNotFound
	}
	return sc, err
}

// ListRehearsalScenarios lists a tenant's scenarios, newest change first.
func (s *Store) ListRehearsalScenarios(ctx context.Context, tenantID string, limit int) ([]RehearsalScenario, error) {
	out := []RehearsalScenario{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+rehearsalScenarioColumns+` FROM rehearsal_scenarios
			WHERE tenant_id = $1 ORDER BY updated_at DESC, id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sc, err := scanRehearsalScenario(rows)
			if err != nil {
				return err
			}
			out = append(out, sc)
		}
		return rows.Err()
	})
	return out, err
}

const rehearsalRunColumns = `id::text, scenario_id::text, scenario_revision, mode, status, verdict, label, tool_version,
	connector_versions, candidate, data_set_digest, expected, observations, detail, started_by, started_at, completed_at`

func scanRehearsalRun(row pgx.Row) (RehearsalRun, error) {
	var r RehearsalRun
	err := row.Scan(&r.ID, &r.ScenarioID, &r.ScenarioRevision, &r.Mode, &r.Status, &r.Verdict, &r.Label, &r.ToolVersion,
		&r.ConnectorVersions, &r.Candidate, &r.DataSetDigest, &r.Expected, &r.Observations, &r.Detail,
		&r.StartedBy, &r.StartedAt, &r.CompletedAt)
	return r, err
}

// GetRehearsalRun reads one run.
func (s *Store) GetRehearsalRun(ctx context.Context, tenantID, id string) (RehearsalRun, error) {
	var r RehearsalRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		r, err = scanRehearsalRun(tx.QueryRow(ctx,
			`SELECT `+rehearsalRunColumns+` FROM rehearsal_runs WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RehearsalRun{}, ErrRehearsalNotFound
	}
	return r, err
}

// ListRehearsalRuns lists a scenario's runs, newest first.
func (s *Store) ListRehearsalRuns(ctx context.Context, tenantID, scenarioID string, limit int) ([]RehearsalRun, error) {
	out := []RehearsalRun{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+rehearsalRunColumns+` FROM rehearsal_runs
			WHERE tenant_id = $1 AND scenario_id = $2 ORDER BY started_at DESC, id LIMIT $3`, tenantID, scenarioID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRehearsalRun(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
