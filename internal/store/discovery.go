// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DiscoverySource is a tenant-owned scan source. Config is deliberately opaque
// JSON so source-specific connectors can carry references without the store
// learning secret shapes; API validation forbids inline secret values.
type DiscoverySource struct {
	ID                      string
	TenantID                string
	Kind                    string
	Name                    string
	Config                  json.RawMessage
	CreatedAt               time.Time
	UpdatedAt               time.Time
	ProjectionEventID       string
	ProjectionEventSequence uint64
}

// DiscoverySchedule is a tenant-owned schedule for a discovery source.
type DiscoverySchedule struct {
	ID              string
	TenantID        string
	SourceID        string
	Name            string
	IntervalSeconds int
	Enabled         bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// DiscoveryRun is one queued/executed discovery run.
type DiscoveryRun struct {
	ID                string
	TenantID          string
	SourceID          string
	ScheduleID        *string
	RetryOfRunID      string
	Status            string
	DryRun            bool
	RequestedBy       string
	Execution         string
	Segment           string
	RequiredAgentRole string
	RequiredAgentID   string
	ExecutedByAgentID string
	Targets           int
	Discovered        int
	Failed            int
	Rejected          int
	Blocked           int
	Error             string
	StartedAt         *time.Time
	CompletedAt       *time.Time
	CreatedAt         time.Time
	// TargetResults are immutable per-target completion facts carried by the
	// completion event. Network, SSH and cloud-provider outcomes are projected
	// into discovery_runs.target_results; CT-log outcomes project into their own
	// per-log read model instead.
	TargetResults []DiscoveryTargetResult `json:"-"`
	// OnlyIfDue is command-side scheduling policy and is never projected. The
	// scheduler sets it so concurrent leader sweeps serialize and re-check the
	// database clock before appending a second run for one schedule.
	OnlyIfDue bool
}

// DiscoveryTargetResult is one bounded target outcome included in a discovery
// completion event. CT monitoring uses it to project log health without a
// scheduler-side write to a derived table (AN-2).
type DiscoveryTargetResult struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Status string `json:"status"`
	Cursor int64  `json:"cursor,omitempty"`
	Error  string `json:"error,omitempty"`
}

// DiscoveryFinding is a metadata-only credential reference produced by a run.
type DiscoveryFinding struct {
	ID string
	// RecordedID is the ID carried by this immutable recorded event. It normally
	// equals ID. During replay of pre-AUD-96 history, ID is the row candidate and
	// RecordedID preserves every legacy payload ID as a triage-resolvable alias.
	RecordedID        string
	TenantID          string
	RunID             string
	SourceID          string
	Kind              string
	Ref               string
	Provenance        string
	Fingerprint       string
	RiskScore         int
	Metadata          json.RawMessage
	DiscoveredAt      time.Time
	TriageStatus      string
	ManagedIdentityID *string
	TriageActor       string
	TriageReason      string
	TriagedAt         *time.Time
	// FirstSeenAt, LastSeenAt and SeenCount describe repeat observations of the
	// same credential by later runs of the same source (one row per observation
	// identity); RunID always names the latest run that observed it.
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	SeenCount   int
	// ProjectionEventSequence is the immutable event's log sequence when the
	// projector applies it (0 for direct writes). The row remembers the newest
	// applied sequence so a catch-up replay of an already applied observation
	// is a no-op instead of a second sighting.
	ProjectionEventSequence int64
}

// ErrDiscoveryFindingConflict means two immutable recorded events claimed the
// same row ID or natural observation key but disagreed on the observation payload.
// Callers must stop replay: choosing either payload would silently rewrite history.
var ErrDiscoveryFindingConflict = errors.New("store: discovery finding identity conflict")

// ErrDiscoveryDeclarationEventConflict means one immutable source/segment event
// identity was replayed with different fields, or a declaration identity collided
// with another tenant/name. The projection must stop: silently choosing either
// value would make the read model depend on writer timing instead of event order.
var ErrDiscoveryDeclarationEventConflict = errors.New("store: discovery declaration event conflict")

// DiscoveryFindingTriageChange is the projected result of a
// discovery.finding.triage_changed event.
type DiscoveryFindingTriageChange struct {
	TenantID          string
	FindingID         string
	Status            string
	ManagedIdentityID *string
	Actor             string
	Reason            string
	ChangedAt         time.Time
	MetadataPatch     json.RawMessage
}

// DiscoveryMonitoringSource is a read-side rollup for one tenant discovery
// source. It is derived from discovery source/schedule/run/finding projections
// and the certificate inventory projection; it never represents a state change.
type DiscoveryMonitoringSource struct {
	SourceID                  string
	TenantID                  string
	Kind                      string
	Name                      string
	Config                    json.RawMessage
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
	ScheduleID                string
	ScheduleEnabled           bool
	MonitoringIntervalSeconds int
	ScheduleUpdatedAt         *time.Time
	LastRunID                 string
	LastRunStatus             string
	LastRunError              string
	LastRunCreatedAt          *time.Time
	LastRunCompletedAt        *time.Time
	LastDiscoveryAt           *time.Time
	RunCount                  int
	CompletedRunCount         int
	FailedRunCount            int
	FindingCount              int
	OpenFindingCount          int
	CertificateInventoryCount int
}

func normalizeJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	return []byte(raw)
}

// ApplyDiscoverySourceUpsertedTx projects a discovery.source.upserted event.
func (s *Store) ApplyDiscoverySourceUpsertedTx(ctx context.Context, tx pgx.Tx, src DiscoverySource) error {
	eventSequence := int64(src.ProjectionEventSequence) // #nosec G115 -- JetStream event sequences are stored in PostgreSQL bigint throughout the projection spine (CWE-190)
	manualWrite := src.ProjectionEventID == "" || src.ProjectionEventSequence == 0
	var applied DiscoverySource
	var appliedSequence int64
	err := tx.QueryRow(ctx,
		`INSERT INTO discovery_sources
		      (id, tenant_id, kind, name, config, created_at, updated_at,
		       projection_event_id, projection_event_sequence)
		      VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9)
		 ON CONFLICT ON CONSTRAINT discovery_sources_pkey DO UPDATE
		      SET kind = CASE WHEN $10 OR (
		              EXCLUDED.projection_event_sequence > discovery_sources.projection_event_sequence
		              AND discovery_sources.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
		          ) THEN EXCLUDED.kind ELSE discovery_sources.kind END,
		          name = CASE WHEN $10 OR (
		              EXCLUDED.projection_event_sequence > discovery_sources.projection_event_sequence
		              AND discovery_sources.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
		          ) THEN EXCLUDED.name ELSE discovery_sources.name END,
		          config = CASE WHEN $10 OR (
		              EXCLUDED.projection_event_sequence > discovery_sources.projection_event_sequence
		              AND discovery_sources.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
		          ) THEN EXCLUDED.config ELSE discovery_sources.config END,
		          updated_at = CASE WHEN $10 OR (
		              EXCLUDED.projection_event_sequence > discovery_sources.projection_event_sequence
		              AND discovery_sources.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
		          ) THEN EXCLUDED.updated_at ELSE discovery_sources.updated_at END,
		          projection_event_id = CASE WHEN $10 THEN discovery_sources.projection_event_id WHEN (
		              EXCLUDED.projection_event_sequence > discovery_sources.projection_event_sequence
		              AND discovery_sources.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
		          ) THEN EXCLUDED.projection_event_id ELSE discovery_sources.projection_event_id END,
		          projection_event_sequence = CASE WHEN $10 THEN discovery_sources.projection_event_sequence WHEN (
		              EXCLUDED.projection_event_sequence > discovery_sources.projection_event_sequence
		              AND discovery_sources.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
		          ) THEN EXCLUDED.projection_event_sequence ELSE discovery_sources.projection_event_sequence END
		    WHERE discovery_sources.tenant_id = EXCLUDED.tenant_id
		 RETURNING id::text, tenant_id::text, kind, name, config, created_at, updated_at,
		           COALESCE(projection_event_id, ''), projection_event_sequence`,
		src.ID, src.TenantID, src.Kind, src.Name, normalizeJSON(src.Config), src.CreatedAt, src.UpdatedAt,
		src.ProjectionEventID, eventSequence, manualWrite).
		Scan(&applied.ID, &applied.TenantID, &applied.Kind, &applied.Name, &applied.Config,
			&applied.CreatedAt, &applied.UpdatedAt, &applied.ProjectionEventID, &appliedSequence)
	if err != nil {
		return discoveryDeclarationWriteError("source", err)
	}
	applied.ProjectionEventSequence = uint64(appliedSequence) // #nosec G115 -- the migration constrains this PostgreSQL bigint to non-negative values (CWE-190)
	if !manualWrite {
		if err := validateDiscoverySourceProjectionResult(src, applied); err != nil {
			return err
		}
	}
	return s.reconcileCTMonitoringFromSourcesTx(ctx, tx, src.TenantID, src.UpdatedAt)
}

func validateDiscoverySourceProjectionResult(expected, applied DiscoverySource) error {
	switch {
	case applied.ProjectionEventSequence < expected.ProjectionEventSequence:
		return fmt.Errorf("%w: source %s did not advance to event %s sequence %d",
			ErrDiscoveryDeclarationEventConflict, expected.ID, expected.ProjectionEventID, expected.ProjectionEventSequence)
	case applied.ProjectionEventSequence > expected.ProjectionEventSequence:
		if applied.ProjectionEventID == expected.ProjectionEventID {
			return fmt.Errorf("%w: source %s reuses event %s at sequences %d and %d",
				ErrDiscoveryDeclarationEventConflict, expected.ID, expected.ProjectionEventID,
				expected.ProjectionEventSequence, applied.ProjectionEventSequence)
		}
		// A later immutable event already won an inline/tail interleaving. The
		// ordered replay of this older event is a safe no-op, not a conflict.
		return nil
	default:
		if applied.ProjectionEventID != expected.ProjectionEventID ||
			applied.ID != expected.ID || applied.TenantID != expected.TenantID ||
			applied.Kind != expected.Kind || applied.Name != expected.Name ||
			!jsonValuesEqual(applied.Config, normalizeJSON(expected.Config)) ||
			!applied.UpdatedAt.Equal(expected.UpdatedAt.UTC().Truncate(time.Microsecond)) {
			return fmt.Errorf("%w: source %s event %s sequence %d differs from the accepted declaration",
				ErrDiscoveryDeclarationEventConflict, expected.ID, expected.ProjectionEventID,
				expected.ProjectionEventSequence)
		}
		return nil
	}
}

func jsonValuesEqual(left, right []byte) bool {
	var l, r any
	if json.Unmarshal(left, &l) != nil || json.Unmarshal(right, &r) != nil {
		return bytes.Equal(left, right)
	}
	return reflect.DeepEqual(l, r)
}

func discoveryDeclarationWriteError(kind string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %s identity belongs to another tenant", ErrDiscoveryDeclarationEventConflict, kind)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23505" || pgErr.Code == "42501") {
		return fmt.Errorf("%w: %s identity or tenant-local name is already bound", ErrDiscoveryDeclarationEventConflict, kind)
	}
	return err
}

// ApplyDiscoveryScheduleUpsertedTx projects a discovery.schedule.upserted event.
func (s *Store) ApplyDiscoveryScheduleUpsertedTx(ctx context.Context, tx pgx.Tx, sched DiscoverySchedule) error {
	tag, err := tx.Exec(ctx,
		`INSERT INTO discovery_schedules (id, tenant_id, source_id, name, interval_seconds, enabled, created_at, updated_at)
		      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT ON CONSTRAINT discovery_schedules_pkey DO UPDATE
		      SET source_id = EXCLUDED.source_id,
		          name = EXCLUDED.name,
		          interval_seconds = EXCLUDED.interval_seconds,
		          enabled = EXCLUDED.enabled,
		          updated_at = EXCLUDED.updated_at
		    WHERE discovery_schedules.tenant_id = EXCLUDED.tenant_id`,
		sched.ID, sched.TenantID, sched.SourceID, sched.Name, sched.IntervalSeconds, sched.Enabled, sched.CreatedAt, sched.UpdatedAt)
	if err != nil {
		return discoveryDeclarationWriteError("schedule", err)
	}
	if tag.RowsAffected() == 0 {
		return discoveryDeclarationWriteError("schedule", pgx.ErrNoRows)
	}
	return nil
}

// ApplyDiscoveryRunQueuedTx projects a discovery.run.queued event.
func (s *Store) ApplyDiscoveryRunQueuedTx(ctx context.Context, tx pgx.Tx, run DiscoveryRun) error {
	execution := run.Execution
	if execution == "" {
		execution = "control_plane"
	}
	// The inline request projector and the durable event-tail projector apply
	// the same discovery.run.queued event. ON CONFLICT is only race-safe on its
	// arbiter (the primary key): two applies that pass that pre-check together
	// both insert speculatively and the loser trips the tenant+ID unique index,
	// which is not arbitrated. Unlike a declaration, a run cannot be re-emitted
	// (the event is already durable and a retry would enqueue a second job), so
	// the race is removed rather than retried: a transaction-scoped advisory lock
	// keyed on the run makes the second apply observe the first's committed row
	// and take the idempotent update.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"discovery-run-projection\x1f"+run.TenantID+"\x1f"+run.ID); err != nil {
		return fmt.Errorf("store: lock discovery run projection: %w", err)
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO discovery_runs
		        (id, tenant_id, source_id, schedule_id, retry_of_run_id, status, dry_run, requested_by,
		         execution, segment, required_agent_role, required_agent_id, created_at)
		      VALUES ($1, $2, $3, $4, NULLIF($5, '')::uuid, $6, $7, $8, $9, $10, $11, NULLIF($12, '')::uuid, $13)
		 ON CONFLICT ON CONSTRAINT discovery_runs_pkey DO UPDATE
		      SET status = EXCLUDED.status,
		          retry_of_run_id = EXCLUDED.retry_of_run_id,
		          dry_run = EXCLUDED.dry_run,
		          requested_by = EXCLUDED.requested_by,
		          execution = EXCLUDED.execution,
		          segment = EXCLUDED.segment,
		          required_agent_role = EXCLUDED.required_agent_role,
		          required_agent_id = EXCLUDED.required_agent_id
		    WHERE discovery_runs.tenant_id = EXCLUDED.tenant_id`,
		run.ID, run.TenantID, run.SourceID, run.ScheduleID, run.RetryOfRunID, run.Status, run.DryRun, run.RequestedBy,
		execution, run.Segment, run.RequiredAgentRole, run.RequiredAgentID, run.CreatedAt)
	if err != nil {
		return discoveryDeclarationWriteError("run", err)
	}
	if tag.RowsAffected() == 0 {
		return discoveryDeclarationWriteError("run", pgx.ErrNoRows)
	}
	return nil
}

// ApplyDiscoveryRunStartedTx projects a discovery.run.started event.
func (s *Store) ApplyDiscoveryRunStartedTx(ctx context.Context, tx pgx.Tx, tenantID, runID string, startedAt time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE discovery_runs
		    SET status = 'running', started_at = $3
		  WHERE tenant_id = $1 AND id = $2 AND status = 'queued'`,
		tenantID, runID, startedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 0 {
		return nil
	}
	// A duplicate producer event may be projected after the terminal event when
	// two copies of one signed receipt race. An existing run is success; a missing
	// run still fails so replay cannot silently skip an absent queue event.
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT true FROM discovery_runs WHERE tenant_id = $1 AND id = $2`, tenantID, runID).Scan(&exists); err != nil {
		return err
	}
	return nil
}

// ApplyDiscoveryFindingRecordedTx projects a discovery.finding.recorded event.
func (s *Store) ApplyDiscoveryFindingRecordedTx(ctx context.Context, tx pgx.Tx, f DiscoveryFinding) error {
	recordedID := f.RecordedID
	if recordedID == "" {
		recordedID = f.ID
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO discovery_findings
		        (id, tenant_id, run_id, source_id, kind, ref, provenance, fingerprint,
		         risk_score, metadata, discovered_at, recorded_ids, first_seen_at, last_seen_at, seen_count,
		         projection_event_sequence)
		      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, ARRAY[$12::uuid], $11, $11, 1, $13)
		 ON CONFLICT DO NOTHING`,
		f.ID, f.TenantID, f.RunID, f.SourceID, f.Kind, f.Ref, f.Provenance, f.Fingerprint,
		f.RiskScore, normalizeJSON(f.Metadata), f.DiscoveredAt, recordedID, f.ProjectionEventSequence)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	// The insert can conflict on either identity boundary: the observation identity
	// (payload ID) or the tenant/run/kind/ref/fingerprint natural key. Lock the
	// winner and decide between three outcomes: an already-projected event is a
	// no-op; the same observation seen again by a later run refreshes the row; a
	// same-run payload that disagrees on the immutable observation is a conflict.
	// PostgreSQL compares metadata as jsonb, so harmless JSON key ordering does not
	// turn an identical observation into a false conflict.
	var (
		existingID, existingRun                                 string
		existingTime                                            time.Time
		existingSequence                                        int64
		alreadyRecorded                                         bool
		sameSource, sameKind, sameRef                           bool
		sameProvenance, sameFingerprint, sameRisk, sameMetadata bool
	)
	err = tx.QueryRow(ctx,
		`SELECT id::text,
		        run_id::text,
		        discovered_at,
		        projection_event_sequence,
		        $11::uuid = ANY(recorded_ids),
		        source_id = $4::uuid,
		        kind = $5,
		        ref = $6,
		        provenance = $7,
		        fingerprint = $8,
		        risk_score = $9,
		        metadata = $10::jsonb
		   FROM discovery_findings
		  WHERE tenant_id = $1::uuid
		    AND (id = $2::uuid OR
		         (run_id = $3::uuid AND kind = $5 AND ref = $6 AND fingerprint = $8))
		  ORDER BY (id = $2::uuid) DESC
		  LIMIT 1
		  FOR UPDATE`,
		f.TenantID, f.ID, f.RunID, f.SourceID, f.Kind, f.Ref, f.Provenance,
		f.Fingerprint, f.RiskScore, normalizeJSON(f.Metadata), recordedID).Scan(
		&existingID, &existingRun, &existingTime, &existingSequence, &alreadyRecorded, &sameSource, &sameKind, &sameRef,
		&sameProvenance, &sameFingerprint, &sameRisk, &sameMetadata)
	if err != nil {
		return fmt.Errorf("store: locate conflicted discovery finding: %w", err)
	}
	if alreadyRecorded && existingSequence >= f.ProjectionEventSequence {
		// The row already remembers this payload and has applied an event at or
		// beyond this one's log sequence: a catch-up replay or an at-least-once
		// redelivery of an observation that is already projected. A repeat sighting
		// by a later run carries a higher sequence and therefore falls through.
		return nil
	}
	identityDifferences := make([]string, 0, 4)
	for field, same := range map[string]bool{
		"source_id": sameSource, "kind": sameKind, "ref": sameRef, "fingerprint": sameFingerprint,
	} {
		if !same {
			identityDifferences = append(identityDifferences, field)
		}
	}
	if len(identityDifferences) > 0 {
		sort.Strings(identityDifferences)
		return fmt.Errorf(
			"%w: tenant=%s natural_key=(run_id=%s kind=%q ref=%q fingerprint=%q) existing_id=%s incoming_id=%s differing_fields=%s",
			ErrDiscoveryFindingConflict, f.TenantID, f.RunID, f.Kind, f.Ref, f.Fingerprint,
			existingID, f.ID, strings.Join(identityDifferences, ","),
		)
	}
	if existingRun != f.RunID {
		// The same credential observed again by a later run of the source: keep the
		// row (and its triage state), move it to the latest run and observation
		// payload, and record the repeat. Replaying the same history reproduces the
		// same counts because every applied event ID is remembered in recorded_ids.
		_, err = tx.Exec(ctx,
			`UPDATE discovery_findings
			    SET run_id = $3::uuid,
			        provenance = $4,
			        risk_score = $5,
			        metadata = $6::jsonb,
			        discovered_at = LEAST(discovered_at, $7),
			        first_seen_at = LEAST(first_seen_at, $7),
			        last_seen_at = GREATEST(last_seen_at, $7),
			        seen_count = seen_count + 1,
			        projection_event_sequence = GREATEST(projection_event_sequence, $9),
			        recorded_ids = ARRAY(
			            SELECT DISTINCT payload_id
			              FROM unnest(recorded_ids || ARRAY[$8::uuid]) AS payload_id
			             ORDER BY payload_id
			        )
			  WHERE tenant_id = $1::uuid AND id = $2::uuid`,
			f.TenantID, existingID, f.RunID, f.Provenance, f.RiskScore, normalizeJSON(f.Metadata),
			f.DiscoveredAt, recordedID, f.ProjectionEventSequence)
		return err
	}
	differences := make([]string, 0, 3)
	for field, same := range map[string]bool{
		"provenance": sameProvenance, "risk_score": sameRisk, "metadata": sameMetadata,
	} {
		if !same {
			differences = append(differences, field)
		}
	}
	if len(differences) > 0 {
		sort.Strings(differences)
		return fmt.Errorf(
			"%w: tenant=%s natural_key=(run_id=%s kind=%q ref=%q fingerprint=%q) existing_id=%s incoming_id=%s differing_fields=%s",
			ErrDiscoveryFindingConflict, f.TenantID, f.RunID, f.Kind, f.Ref, f.Fingerprint,
			existingID, f.ID, strings.Join(differences, ","),
		)
	}

	// Same run, same observation, different payload ID: a byte-for-byte semantic
	// replay of pre-AUD-96 history. Keep the earliest row identity and remember
	// every payload ID as a triage-resolvable alias.
	canonicalID := existingID
	if f.DiscoveredAt.Before(existingTime) || (f.DiscoveredAt.Equal(existingTime) && f.ID < existingID) {
		canonicalID = f.ID
	}
	_, err = tx.Exec(ctx,
		`UPDATE discovery_findings
		    SET id = $3::uuid,
		        discovered_at = LEAST(discovered_at, $4),
		        first_seen_at = LEAST(first_seen_at, $4),
		        last_seen_at = GREATEST(last_seen_at, $4),
		        projection_event_sequence = GREATEST(projection_event_sequence, $6),
		        recorded_ids = ARRAY(
		            SELECT DISTINCT payload_id
		              FROM unnest(recorded_ids || ARRAY[$5::uuid, $2::uuid, $3::uuid]) AS payload_id
		             ORDER BY payload_id
		        )
		  WHERE tenant_id = $1::uuid AND id = $2::uuid`,
		f.TenantID, existingID, canonicalID, f.DiscoveredAt, recordedID, f.ProjectionEventSequence)
	return err
}

// ApplyDiscoveryFindingRecordedWithAlertTx projects one finding and its
// canonical urgent-risk notification intent atomically (AN-2/AN-6). The caller
// supplies a closed, credential-free alert payload derived from the same score
// contract used by the headline summary. Empty alert fields mean this finding
// is below the urgent bands.
func (s *Store) ApplyDiscoveryFindingRecordedWithAlertTx(
	ctx context.Context,
	tx pgx.Tx,
	f DiscoveryFinding,
	alertDestination string,
	alertPayload []byte,
	alertKey string,
) error {
	if (alertDestination == "") != (len(alertPayload) == 0) ||
		(alertDestination == "") != (alertKey == "") {
		return errors.New("store: discovery risk alert intent is incomplete")
	}
	if err := s.ApplyDiscoveryFindingRecordedTx(ctx, tx, f); err != nil {
		return err
	}
	if alertDestination == "" {
		return nil
	}

	// The finding's natural-key insert serializes exact observation races. This
	// second tenant+receiver lock also protects callers whose event IDs differ
	// but intentionally bind to the same semantic alert key.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"discovery-risk-alert\x1f"+f.TenantID+"\x1f"+alertKey); err != nil {
		return fmt.Errorf("store: lock discovery risk alert: %w", err)
	}
	var existingDestination string
	var existingPayload []byte
	err := tx.QueryRow(ctx,
		`SELECT destination, payload FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2 ORDER BY id LIMIT 1`,
		f.TenantID, alertKey).Scan(&existingDestination, &existingPayload)
	if err == nil {
		if existingDestination != alertDestination || !bytes.Equal(existingPayload, alertPayload) {
			return fmt.Errorf("%w: discovery risk alert key is already bound", ErrIdempotencyConflict)
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 VALUES ($1, $2, $2, $3, $4)`,
		f.TenantID, alertDestination, alertPayload, alertKey); err != nil {
		return fmt.Errorf("store: enqueue discovery risk alert: %w", err)
	}
	return nil
}

// ApplyDiscoveryFindingTriageChangedTx projects a discovery.finding.triage_changed event.
func (s *Store) ApplyDiscoveryFindingTriageChangedTx(ctx context.Context, tx pgx.Tx, ch DiscoveryFindingTriageChange) error {
	tag, err := tx.Exec(ctx,
		`UPDATE discovery_findings
		    SET triage_status = $3,
		        managed_identity_id = $4,
		        triage_actor = $5,
		        triage_reason = $6,
		        triaged_at = $7,
		        metadata = CASE
		            WHEN $8::jsonb IS NULL THEN metadata
		            ELSE metadata || $8::jsonb
		        END
		  WHERE tenant_id = $1 AND (id = $2 OR $2::uuid = ANY(recorded_ids))`,
		ch.TenantID, ch.FindingID, ch.Status, ch.ManagedIdentityID, ch.Actor, ch.Reason, ch.ChangedAt, ch.MetadataPatch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplyDiscoveryRunCompletedTx projects a discovery.run.completed event.
func (s *Store) ApplyDiscoveryRunCompletedTx(ctx context.Context, tx pgx.Tx, run DiscoveryRun) error {
	projected := make([]DiscoveryTargetResult, 0, len(run.TargetResults))
	for _, result := range run.TargetResults {
		if result.Kind == "ct_log" {
			continue
		}
		projected = append(projected, result)
	}
	targetResultsJSON, err := json.Marshal(projected)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE discovery_runs
		    SET status = $3,
		        targets = $4,
		        discovered = $5,
		        failed = $6,
		        rejected = $7,
		        blocked = $8,
		        error = $9,
		        executed_by_agent_id = NULLIF($10, '')::uuid,
		        completed_at = $11,
		        target_results = $12::jsonb
		  WHERE tenant_id = $1 AND id = $2`,
		run.TenantID, run.ID, run.Status, run.Targets, run.Discovered, run.Failed,
		run.Rejected, run.Blocked, run.Error, run.ExecutedByAgentID, run.CompletedAt, targetResultsJSON)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// GetDiscoverySource loads a source in its tenant context.
func (s *Store) GetDiscoverySource(ctx context.Context, tenantID, id string) (DiscoverySource, error) {
	var out DiscoverySource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDiscoverySource(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, kind, name, config, created_at, updated_at
			   FROM discovery_sources WHERE tenant_id = $1 AND id = $2`, tenantID, id), &out)
	})
	return out, err
}

// GetDiscoverySourceByName loads the tenant-local identity used by the
// source-upsert command. Name is unique only inside one tenant; the predicate
// therefore carries tenant_id even though RLS is also active (AN-1).
func (s *Store) GetDiscoverySourceByName(ctx context.Context, tenantID, name string) (DiscoverySource, error) {
	var out DiscoverySource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDiscoverySource(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, kind, name, config, created_at, updated_at
			   FROM discovery_sources WHERE tenant_id = $1 AND name = $2`, tenantID, name), &out)
	})
	return out, err
}

// ListDiscoverySourcesPage lists tenant sources by id keyset.
func (s *Store) ListDiscoverySourcesPage(ctx context.Context, tenantID, afterID string, limit int) ([]DiscoverySource, error) {
	var out []DiscoverySource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, name, config, created_at, updated_at
			   FROM discovery_sources
			  WHERE tenant_id = $1 AND id > $2
			  ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var src DiscoverySource
			if err := scanDiscoverySource(rows, &src); err != nil {
				return err
			}
			out = append(out, src)
		}
		return rows.Err()
	})
	return out, err
}

// ListDiscoverySchedulesPage lists tenant schedules by id keyset.
func (s *Store) ListDiscoverySchedulesPage(ctx context.Context, tenantID, afterID string, limit int) ([]DiscoverySchedule, error) {
	var out []DiscoverySchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, source_id::text, name, interval_seconds, enabled, created_at, updated_at
			   FROM discovery_schedules
			  WHERE tenant_id = $1 AND id > $2
			  ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sched DiscoverySchedule
			if err := rows.Scan(&sched.ID, &sched.TenantID, &sched.SourceID, &sched.Name,
				&sched.IntervalSeconds, &sched.Enabled, &sched.CreatedAt, &sched.UpdatedAt); err != nil {
				return err
			}
			out = append(out, sched)
		}
		return rows.Err()
	})
	return out, err
}

// TenantsWithEnabledDiscoverySchedules enumerates the tenants that own at
// least one enabled discovery schedule, so the leader-only schedule ticker can
// sweep each tenant under its own RLS context.
func (s *Store) TenantsWithEnabledDiscoverySchedules(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants have enabled discovery schedules so the leader-only scheduler can sweep each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM discovery_schedules WHERE enabled ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DiscoverySchedulesDue returns the tenant's enabled schedules that are due to
// run at now: their source has no in-flight run (queued/running) and no run —
// of any outcome — newer than the schedule's interval, so a failed attempt
// retries on the next interval instead of hot-looping every sweep. limit
// bounds one sweep's work (AN-7 discipline at the query, before the queue).
func (s *Store) DiscoverySchedulesDue(ctx context.Context, tenantID string, now time.Time, limit int) ([]DiscoverySchedule, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []DiscoverySchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT s.id::text, s.tenant_id::text, s.source_id::text, s.name, s.interval_seconds, s.enabled, s.created_at, s.updated_at
			   FROM discovery_schedules s
			  WHERE s.tenant_id = $1 AND s.enabled
			    AND NOT EXISTS (
			      SELECT 1 FROM discovery_runs r
			       WHERE r.tenant_id = s.tenant_id
			         AND r.source_id = s.source_id
			         AND (r.status IN ('queued', 'running')
			              OR r.created_at > $2::timestamptz - make_interval(secs => GREATEST(s.interval_seconds, 1)))
			    )
			  ORDER BY s.created_at, s.id
			  LIMIT $3`, tenantID, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sched DiscoverySchedule
			if err := rows.Scan(&sched.ID, &sched.TenantID, &sched.SourceID, &sched.Name,
				&sched.IntervalSeconds, &sched.Enabled, &sched.CreatedAt, &sched.UpdatedAt); err != nil {
				return err
			}
			out = append(out, sched)
		}
		return rows.Err()
	})
	return out, err
}

// GetDiscoverySchedule loads a schedule in its tenant context.
func (s *Store) GetDiscoverySchedule(ctx context.Context, tenantID, id string) (DiscoverySchedule, error) {
	var out DiscoverySchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, source_id::text, name, interval_seconds, enabled, created_at, updated_at
			   FROM discovery_schedules WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&out.ID, &out.TenantID, &out.SourceID, &out.Name, &out.IntervalSeconds, &out.Enabled, &out.CreatedAt, &out.UpdatedAt)
	})
	return out, err
}

// GetDiscoveryRun loads a run in its tenant context.
func (s *Store) GetDiscoveryRun(ctx context.Context, tenantID, id string) (DiscoveryRun, error) {
	var out DiscoveryRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDiscoveryRun(tx.QueryRow(ctx, `SELECT id::text, tenant_id::text, source_id::text, schedule_id::text,
		              COALESCE(retry_of_run_id::text, ''), status, dry_run,
		              requested_by, execution, segment, required_agent_role,
		              COALESCE(required_agent_id::text, ''), COALESCE(executed_by_agent_id::text, ''),
		              targets, discovered, failed, rejected, blocked, error, started_at, completed_at, created_at,
		              target_results
		         FROM discovery_runs
		        WHERE tenant_id = $1 AND id = $2`, tenantID, id), &out)
	})
	return out, err
}

// GetLatestDiscoveryRunForSource loads the newest run for one tenant-owned
// source. The source predicate is part of the query so a caller cannot learn a
// run from another source or tenant while building an operator status view.
func (s *Store) GetLatestDiscoveryRunForSource(ctx context.Context, tenantID, sourceID string) (DiscoveryRun, error) {
	var out DiscoveryRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDiscoveryRun(tx.QueryRow(ctx, `SELECT id::text, tenant_id::text, source_id::text, schedule_id::text,
		              COALESCE(retry_of_run_id::text, ''), status, dry_run,
		              requested_by, execution, segment, required_agent_role,
		              COALESCE(required_agent_id::text, ''), COALESCE(executed_by_agent_id::text, ''),
		              targets, discovered, failed, rejected, blocked, error, started_at, completed_at, created_at,
		              target_results
		         FROM discovery_runs
		        WHERE tenant_id = $1 AND source_id = $2
		     ORDER BY created_at DESC, id DESC
		        LIMIT 1`, tenantID, sourceID), &out)
	})
	return out, err
}

// ListDiscoveryRunsPage lists tenant runs by id keyset.
func (s *Store) ListDiscoveryRunsPage(ctx context.Context, tenantID, afterID string, limit int) ([]DiscoveryRun, error) {
	var out []DiscoveryRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, source_id::text, schedule_id::text,
		              COALESCE(retry_of_run_id::text, ''), status, dry_run,
		              requested_by, execution, segment, required_agent_role,
		              COALESCE(required_agent_id::text, ''), COALESCE(executed_by_agent_id::text, ''),
		              targets, discovered, failed, rejected, blocked, error, started_at, completed_at, created_at,
		              target_results
		         FROM discovery_runs
		        WHERE tenant_id = $1 AND id > $2
		     ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var run DiscoveryRun
			if err := scanDiscoveryRun(rows, &run); err != nil {
				return err
			}
			out = append(out, run)
		}
		return rows.Err()
	})
	return out, err
}

// ListDiscoveryFindingsPage lists tenant findings, optionally scoped to one run.
func (s *Store) ListDiscoveryFindingsPage(ctx context.Context, tenantID, runID, afterID string, limit int) ([]DiscoveryFinding, error) {
	var out []DiscoveryFinding
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		sql := `SELECT id::text, tenant_id::text, run_id::text, source_id::text, kind, ref,
		              provenance, fingerprint, risk_score, metadata, discovered_at,
		              triage_status, managed_identity_id::text, triage_actor, triage_reason, triaged_at,
		              first_seen_at, last_seen_at, seen_count
		         FROM discovery_findings
		        WHERE tenant_id = $1 AND id > $2`
		args := []any{tenantID, afterID, limit}
		if runID != "" {
			sql += ` AND run_id = $4`
			args = append(args, runID)
		}
		sql += ` ORDER BY id LIMIT $3`
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f DiscoveryFinding
			if err := scanDiscoveryFinding(rows, &f); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// GetDiscoveryFinding loads one tenant-scoped discovery finding.
func (s *Store) GetDiscoveryFinding(ctx context.Context, tenantID, id string) (DiscoveryFinding, error) {
	var out DiscoveryFinding
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDiscoveryFinding(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, run_id::text, source_id::text, kind, ref,
			        provenance, fingerprint, risk_score, metadata, discovered_at,
			        triage_status, managed_identity_id::text, triage_actor, triage_reason, triaged_at,
			        first_seen_at, last_seen_at, seen_count
			   FROM discovery_findings
			  WHERE tenant_id = $1 AND (id = $2 OR $2::uuid = ANY(recorded_ids))`, tenantID, id), &out)
	})
	return out, err
}

// ListDiscoveryMonitoringSources returns a tenant-scoped centralized monitoring
// rollup. It reads only projected tables, so replaying the event log rebuilds the
// data this query summarizes.
func (s *Store) ListDiscoveryMonitoringSources(ctx context.Context, tenantID string) ([]DiscoveryMonitoringSource, error) {
	var out []DiscoveryMonitoringSource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT s.id::text,
			        s.tenant_id::text,
			        s.kind,
			        s.name,
			        s.config,
			        s.created_at,
			        s.updated_at,
			        COALESCE(sched.id, '') AS schedule_id,
			        COALESCE(sched.enabled, false) AS schedule_enabled,
			        COALESCE(sched.interval_seconds, 0) AS monitoring_interval_seconds,
			        sched.updated_at AS schedule_updated_at,
			        COALESCE(last_run.id, '') AS last_run_id,
			        COALESCE(last_run.status, '') AS last_run_status,
			        COALESCE(last_run.error, '') AS last_run_error,
			        last_run.created_at AS last_run_created_at,
			        last_run.completed_at AS last_run_completed_at,
			        finding_counts.last_discovery_at,
			        run_counts.run_count,
			        run_counts.completed_run_count,
			        run_counts.failed_run_count,
			        finding_counts.finding_count,
			        finding_counts.open_finding_count,
			        cert_counts.certificate_inventory_count
			   FROM discovery_sources s
		  LEFT JOIN LATERAL (
			        SELECT ds.id::text, ds.enabled, ds.interval_seconds, ds.updated_at
			          FROM discovery_schedules ds
			         WHERE ds.tenant_id = $1 AND ds.source_id = s.id
			         ORDER BY ds.enabled DESC, ds.updated_at DESC, ds.id DESC
			         LIMIT 1
		       ) sched ON true
		  LEFT JOIN LATERAL (
			        SELECT dr.id::text, dr.status, dr.error, dr.created_at, dr.completed_at
			          FROM discovery_runs dr
			         WHERE dr.tenant_id = $1 AND dr.source_id = s.id
			         ORDER BY dr.created_at DESC, dr.id DESC
			         LIMIT 1
		       ) last_run ON true
		  LEFT JOIN LATERAL (
			        SELECT count(*)::integer AS run_count,
			               count(*) FILTER (WHERE dr.status IN ('succeeded', 'partial'))::integer AS completed_run_count,
			               count(*) FILTER (WHERE dr.status = 'failed')::integer AS failed_run_count
			          FROM discovery_runs dr
			         WHERE dr.tenant_id = $1 AND dr.source_id = s.id
		       ) run_counts ON true
		  LEFT JOIN LATERAL (
			        SELECT count(*)::integer AS finding_count,
			               count(*) FILTER (WHERE df.triage_status = 'unmanaged')::integer AS open_finding_count,
			               max(df.discovered_at) AS last_discovery_at
			          FROM discovery_findings df
			         WHERE df.tenant_id = $1 AND df.source_id = s.id
		       ) finding_counts ON true
		  LEFT JOIN LATERAL (
			        SELECT count(*)::integer AS certificate_inventory_count
			          FROM certificates c
			         WHERE c.tenant_id = $1 AND c.source = 'discovery:' || s.kind
		       ) cert_counts ON true
			  WHERE s.tenant_id = $1
			  ORDER BY s.kind, s.name, s.id`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row DiscoveryMonitoringSource
			if err := rows.Scan(&row.SourceID, &row.TenantID, &row.Kind, &row.Name, &row.Config,
				&row.CreatedAt, &row.UpdatedAt, &row.ScheduleID, &row.ScheduleEnabled,
				&row.MonitoringIntervalSeconds, &row.ScheduleUpdatedAt, &row.LastRunID,
				&row.LastRunStatus, &row.LastRunError, &row.LastRunCreatedAt,
				&row.LastRunCompletedAt, &row.LastDiscoveryAt, &row.RunCount,
				&row.CompletedRunCount, &row.FailedRunCount, &row.FindingCount,
				&row.OpenFindingCount, &row.CertificateInventoryCount); err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

func scanDiscoverySource(row rowScanner, src *DiscoverySource) error {
	var cfg []byte
	if err := row.Scan(&src.ID, &src.TenantID, &src.Kind, &src.Name, &cfg, &src.CreatedAt, &src.UpdatedAt); err != nil {
		return err
	}
	src.Config = json.RawMessage(cfg)
	return nil
}

func scanDiscoveryRun(row rowScanner, run *DiscoveryRun) error {
	var targetResults []byte
	if err := row.Scan(&run.ID, &run.TenantID, &run.SourceID, &run.ScheduleID, &run.RetryOfRunID, &run.Status, &run.DryRun,
		&run.RequestedBy, &run.Execution, &run.Segment, &run.RequiredAgentRole, &run.RequiredAgentID,
		&run.ExecutedByAgentID, &run.Targets, &run.Discovered, &run.Failed, &run.Rejected, &run.Blocked, &run.Error,
		&run.StartedAt, &run.CompletedAt, &run.CreatedAt, &targetResults); err != nil {
		return err
	}
	run.TargetResults = nil
	if len(targetResults) > 0 && string(targetResults) != "[]" {
		if err := json.Unmarshal(targetResults, &run.TargetResults); err != nil {
			return fmt.Errorf("store: decode discovery run target results: %w", err)
		}
	}
	return nil
}

func scanDiscoveryFinding(row rowScanner, f *DiscoveryFinding) error {
	var meta []byte
	if err := row.Scan(&f.ID, &f.TenantID, &f.RunID, &f.SourceID, &f.Kind, &f.Ref,
		&f.Provenance, &f.Fingerprint, &f.RiskScore, &meta, &f.DiscoveredAt,
		&f.TriageStatus, &f.ManagedIdentityID, &f.TriageActor, &f.TriageReason, &f.TriagedAt,
		&f.FirstSeenAt, &f.LastSeenAt, &f.SeenCount); err != nil {
		return err
	}
	f.Metadata = json.RawMessage(meta)
	return nil
}
