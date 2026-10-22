// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// PQC pilot read model (A28/A29). Rows here are projections of the immutable
// pqc.pilot.* events; every reader is tenant-bound under RLS (AN-1).

// PQCPilot is one staged post-quantum rollout proof.
type PQCPilot struct {
	ID             string
	TenantID       string
	Name           string
	AuthorityID    string
	RequestedBy    string
	Status         string // running | halted | completed
	WaveCount      int
	CurrentWave    int
	HaltedAtWave   string
	VerdictSummary string
	SignedReport   string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	FinishedAt     *time.Time
	Waves          []PQCPilotWave
}

// PQCPilotTarget is one endpoint a wave probes, bound to the exact leaf it
// should present.
type PQCPilotTarget struct {
	TargetID    string `json:"target_id"`
	Address     string `json:"address"`
	ServerName  string `json:"server_name,omitempty"`
	Connector   string `json:"connector,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

// PQCPilotResult is one target's classified handshake evidence.
type PQCPilotResult struct {
	TargetID        string    `json:"target_id"`
	Outcome         string    `json:"outcome"`
	HandshakeMillis int64     `json:"handshake_ms"`
	ChainBytes      int       `json:"chain_bytes"`
	Detail          string    `json:"detail,omitempty"`
	EvidenceDigest  string    `json:"evidence_digest,omitempty"`
	ObservedAt      time.Time `json:"observed_at"`
}

// PQCPilotVerdict is the compat-lab verdict over the evidence accumulated
// through a wave.
type PQCPilotVerdict struct {
	Ready        bool   `json:"ready"`
	Halt         bool   `json:"halt"`
	Summary      string `json:"summary"`
	Negotiated   int    `json:"negotiated"`
	Rejected     int    `json:"rejected"`
	Unreachable  int    `json:"unreachable"`
	NotAttempted int    `json:"not_attempted"`
}

// PQCPilotWave is one ordered stage; the first wave is the canary.
type PQCPilotWave struct {
	PilotID        string
	Index          int
	Name           string
	Targets        []PQCPilotTarget
	Status         string // pending | probing | assessed | skipped
	OutboxID       *int64
	IdempotencyKey string
	Results        []PQCPilotResult
	Verdict        *PQCPilotVerdict
	DispatchedAt   *time.Time
	AssessedAt     *time.Time
}

// ErrPQCPilotExists is returned when a start replays an id already projected.
var ErrPQCPilotExists = errors.New("store: pqc pilot already exists")

func (s *Store) ApplyPQCPilotStartedTx(ctx context.Context, tx pgx.Tx, pilot PQCPilot) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO pqc_pilots (tenant_id, id, name, authority_id, requested_by, status, wave_count, current_wave, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, 'running', $6, 0, $7, $7)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		pilot.TenantID, pilot.ID, pilot.Name, pilot.AuthorityID, pilot.RequestedBy, len(pilot.Waves), pilot.CreatedAt)
	if err != nil {
		return err
	}
	for _, wave := range pilot.Waves {
		targets, err := json.Marshal(wave.Targets)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO pqc_pilot_waves (tenant_id, pilot_id, wave_index, name, targets, status)
			 VALUES ($1, $2, $3, $4, $5, 'pending')
			 ON CONFLICT (tenant_id, pilot_id, wave_index) DO NOTHING`,
			pilot.TenantID, pilot.ID, wave.Index, wave.Name, targets); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ApplyPQCPilotWaveDispatchedTx(ctx context.Context, tx pgx.Tx, tenantID, pilotID string, wave int, outboxID int64, idempotencyKey string, at time.Time) error {
	if _, err := tx.Exec(ctx,
		`UPDATE pqc_pilot_waves SET status = 'probing', outbox_id = $4, idempotency_key = $5, dispatched_at = $6
		  WHERE tenant_id = $1 AND pilot_id = $2 AND wave_index = $3 AND status = 'pending'`,
		tenantID, pilotID, wave, outboxID, idempotencyKey, at); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`UPDATE pqc_pilots SET current_wave = GREATEST(current_wave, $3), updated_at = $4
		  WHERE tenant_id = $1 AND id = $2`, tenantID, pilotID, wave, at)
	return err
}

// PQCPilotWaveAssessment is the projected outcome of one wave.
type PQCPilotWaveAssessment struct {
	PilotID      string
	Wave         int
	Results      []PQCPilotResult
	Verdict      PQCPilotVerdict
	Status       string // the pilot's status after this wave
	HaltedAtWave string
	AssessedAt   time.Time
}

func (s *Store) ApplyPQCPilotWaveAssessedTx(ctx context.Context, tx pgx.Tx, tenantID string, a PQCPilotWaveAssessment) error {
	results, err := json.Marshal(a.Results)
	if err != nil {
		return err
	}
	verdict, err := json.Marshal(a.Verdict)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE pqc_pilot_waves SET status = 'assessed', results = $4, verdict = $5, assessed_at = $6
		  WHERE tenant_id = $1 AND pilot_id = $2 AND wave_index = $3`,
		tenantID, a.PilotID, a.Wave, results, verdict, a.AssessedAt); err != nil {
		return err
	}
	var finished *time.Time
	if a.Status != "running" {
		at := a.AssessedAt
		finished = &at
		// Waves after a halt never run; say so rather than leaving them pending.
		if _, err := tx.Exec(ctx,
			`UPDATE pqc_pilot_waves SET status = 'skipped'
			  WHERE tenant_id = $1 AND pilot_id = $2 AND wave_index > $3 AND status = 'pending'`,
			tenantID, a.PilotID, a.Wave); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx,
		`UPDATE pqc_pilots SET status = $3, halted_at_wave = $4, verdict_summary = $5, updated_at = $6, finished_at = COALESCE($7, finished_at)
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, a.PilotID, a.Status, a.HaltedAtWave, a.Verdict.Summary, a.AssessedAt, finished)
	return err
}

func (s *Store) ApplyPQCPilotReportSignedTx(ctx context.Context, tx pgx.Tx, tenantID, pilotID, signedReport string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE pqc_pilots SET signed_report = $3, updated_at = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantID, pilotID, signedReport, at)
	return err
}

func (s *Store) LockPQCPilotTx(ctx context.Context, tx pgx.Tx, tenantID, pilotID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1 || ':pqc-pilot:' || $2))`, tenantID, pilotID)
	return err
}

func (s *Store) GetPQCPilotTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (PQCPilot, error) {
	var p PQCPilot
	err := tx.QueryRow(ctx,
		`SELECT id::text, tenant_id::text, name, authority_id, requested_by, status, wave_count, current_wave,
		        halted_at_wave, verdict_summary, signed_report, created_at, updated_at, finished_at
		   FROM pqc_pilots WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(
		&p.ID, &p.TenantID, &p.Name, &p.AuthorityID, &p.RequestedBy, &p.Status, &p.WaveCount, &p.CurrentWave,
		&p.HaltedAtWave, &p.VerdictSummary, &p.SignedReport, &p.CreatedAt, &p.UpdatedAt, &p.FinishedAt)
	if err != nil {
		return PQCPilot{}, err
	}
	rows, err := tx.Query(ctx,
		`SELECT pilot_id::text, wave_index, name, targets, status, outbox_id, idempotency_key, results, verdict, dispatched_at, assessed_at
		   FROM pqc_pilot_waves WHERE tenant_id = $1 AND pilot_id = $2 ORDER BY wave_index`, tenantID, id)
	if err != nil {
		return PQCPilot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var w PQCPilotWave
		var targets, results, verdict []byte
		if err := rows.Scan(&w.PilotID, &w.Index, &w.Name, &targets, &w.Status, &w.OutboxID, &w.IdempotencyKey,
			&results, &verdict, &w.DispatchedAt, &w.AssessedAt); err != nil {
			return PQCPilot{}, err
		}
		if err := json.Unmarshal(targets, &w.Targets); err != nil {
			return PQCPilot{}, fmt.Errorf("store: pqc pilot wave targets: %w", err)
		}
		if len(results) > 0 {
			if err := json.Unmarshal(results, &w.Results); err != nil {
				return PQCPilot{}, fmt.Errorf("store: pqc pilot wave results: %w", err)
			}
		}
		if len(verdict) > 0 {
			var v PQCPilotVerdict
			if err := json.Unmarshal(verdict, &v); err != nil {
				return PQCPilot{}, fmt.Errorf("store: pqc pilot wave verdict: %w", err)
			}
			w.Verdict = &v
		}
		p.Waves = append(p.Waves, w)
	}
	return p, rows.Err()
}

func (s *Store) GetPQCPilot(ctx context.Context, tenantID, id string) (PQCPilot, error) {
	var out PQCPilot
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.GetPQCPilotTx(ctx, tx, tenantID, id)
		return err
	})
	return out, err
}

// ListPQCPilotsPage lists pilots newest first, without their waves.
func (s *Store) ListPQCPilotsPage(ctx context.Context, tenantID, after string, limit int) ([]PQCPilot, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []PQCPilot
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, authority_id, requested_by, status, wave_count, current_wave,
			        halted_at_wave, verdict_summary, signed_report, created_at, updated_at, finished_at
			   FROM pqc_pilots
			  WHERE tenant_id = $1 AND ($2 = '' OR id::text > $2)
			  ORDER BY id LIMIT $3`, tenantID, strings.TrimSpace(after), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p PQCPilot
			if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.AuthorityID, &p.RequestedBy, &p.Status, &p.WaveCount, &p.CurrentWave,
				&p.HaltedAtWave, &p.VerdictSummary, &p.SignedReport, &p.CreatedAt, &p.UpdatedAt, &p.FinishedAt); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}
