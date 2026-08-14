// SPDX-License-Identifier: MPL-2.0

package backup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

const (
	postgresStateFormatTag  = "trstctl-postgres-state-backup"
	postgresStateTrailerTag = "trstctl-postgres-state-backup-trailer"
	postgresStateVersion    = 1
)

type postgresStateHeader struct {
	Format           string    `json:"format"`
	Version          int       `json:"version"`
	CreatedAt        time.Time `json:"created_at"`
	Tables           []string  `json:"tables"`
	EventCutSequence uint64    `json:"event_cut_sequence,omitempty"`
}

type postgresStateRecord struct {
	Table string          `json:"table"`
	Row   json.RawMessage `json:"row"`
}

type postgresStateTrailer struct {
	Format           string         `json:"format"`
	SHA256           string         `json:"sha256"`
	Records          int            `json:"records"`
	Tables           map[string]int `json:"tables"`
	EventCutSequence uint64         `json:"event_cut_sequence,omitempty"`
}

// PostgresStateSummary reports the row counts written or restored for the
// independent PostgreSQL state artifact.
type PostgresStateSummary struct {
	Tables           map[string]int            `json:"tables"`
	Records          int                       `json:"records"`
	EventCutSequence uint64                    `json:"event_cut_sequence,omitempty"`
	AuditCheckpoints []AuditCheckpointBoundary `json:"audit_checkpoints,omitempty"`
}

// AuditCheckpointBoundary is the minimum authenticated PostgreSQL evidence
// needed to prove that a paired event artifact still contains every AN-2 source
// envelope hidden by a logical audit-retention checkpoint.
type AuditCheckpointBoundary struct {
	TenantID    string `json:"tenant_id"`
	BoundarySeq uint64 `json:"boundary_sequence"`
	RecordCount int    `json:"record_count"`
}

// WritePostgresState writes all independent PostgreSQL state classified in the
// backup manifest to w as JSONL with an integrity trailer. Projection/read-model
// tables are intentionally excluded: the event log restores those.
func WritePostgresState(ctx context.Context, st *store.Store, w io.Writer) (PostgresStateSummary, error) {
	return WritePostgresStateAtCut(ctx, st, w, 0)
}

// BeginPostgresStateSnapshot opens and pins the read-only repeatable-read
// snapshot used for PostgreSQL state export. Full backups call this while holding
// the backup write fence after capturing the paired event-log cut, so no tenant
// mutation can land between the event boundary and the PostgreSQL snapshot.
// PostgresStateSnapshot is an attested PostgreSQL-state export transaction.
// Its transaction is deliberately private: callers can stream only snapshots
// that BeginPostgresStateSnapshot pinned under the backup/privacy fence.
type PostgresStateSnapshot struct {
	tx pgx.Tx
}

func (s *PostgresStateSnapshot) Commit(ctx context.Context) error {
	if s == nil || s.tx == nil {
		return errors.New("backup: postgres-state snapshot is not active")
	}
	err := s.tx.Commit(ctx)
	s.tx = nil
	return err
}

func (s *PostgresStateSnapshot) Rollback(ctx context.Context) error {
	if s == nil || s.tx == nil {
		return errors.New("backup: postgres-state snapshot is not active")
	}
	err := s.tx.Rollback(ctx)
	s.tx = nil
	return err
}

func (s *PostgresStateSnapshot) transaction() (pgx.Tx, error) {
	if s == nil || s.tx == nil {
		return nil, errors.New("backup: postgres-state snapshot is not active")
	}
	return s.tx, nil
}

func BeginPostgresStateSnapshot(ctx context.Context, st *store.Store) (*PostgresStateSnapshot, error) {
	tx, err := st.BeginPostgresStateSnapshotTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("backup: begin postgres state snapshot: %w", err)
	}
	if err := guardPostgresStateSnapshotTx(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return &PostgresStateSnapshot{tx: tx}, nil
}

func guardPostgresStateSnapshotTx(ctx context.Context, tx pgx.Tx) error {
	var activePrivacyPreparation bool
	//trstctl:system-query — this cross-tenant system preflight reveals no tenant, subject, selector, actor, or payload; it only prevents pairing sanitized event history with unfinished pre-erasure SQL (AN-1 exemption).
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM privacy_subject_erasure_preparations)`,
	).Scan(&activePrivacyPreparation); err != nil {
		return fmt.Errorf("backup: inspect privacy erasure preparations in pinned snapshot: %w", err)
	}
	if activePrivacyPreparation {
		return store.ErrPrivacySubjectErasurePreparationActive
	}
	return nil
}

// WritePostgresStateAtCut writes PostgreSQL state and records the event-log cut
// this artifact is paired with.
func WritePostgresStateAtCut(ctx context.Context, st *store.Store, w io.Writer, eventCut uint64) (PostgresStateSummary, error) {
	tx, err := BeginPostgresStateSnapshot(ctx, st)
	if err != nil {
		return PostgresStateSummary{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	summary, err := WritePostgresStateTx(ctx, tx, w, eventCut)
	if err != nil {
		return summary, err
	}
	if err := tx.Commit(ctx); err != nil {
		return summary, fmt.Errorf("backup: finish postgres state export: %w", err)
	}
	return summary, nil
}

// WritePostgresStateTx writes PostgreSQL state from an attested read-only,
// repeatable-read snapshot. Full backup uses a snapshot pinned under the backup
// write fence, paired with the event-log cut in the artifact header.
func WritePostgresStateTx(ctx context.Context, snapshot *PostgresStateSnapshot, w io.Writer, eventCut uint64) (PostgresStateSummary, error) {
	// WritePostgresStateTx is exported for the full-backup coordinator, so defend
	// it with an attested snapshot that external callers cannot construct around
	// a transaction pinned before the fence. Reassert the transaction-scoped
	// shared grant before the first artifact byte (the safe Begin path already
	// holds it) and inspect preparation state in this exact snapshot.
	tx, err := snapshot.transaction()
	if err != nil {
		return PostgresStateSummary{}, err
	}
	if _, err := tx.Exec(ctx,
		"SELECT pg_advisory_xact_lock_shared($1)",
		store.BackupWriteFenceAdvisoryLockKey,
	); err != nil {
		return PostgresStateSummary{}, fmt.Errorf("backup: acquire postgres-state export fence: %w", err)
	}
	if err := guardPostgresStateSnapshotTx(ctx, tx); err != nil {
		return PostgresStateSummary{}, err
	}
	tables := postgresStateTables()
	bw := bufio.NewWriter(w)
	dig := newDigest(nil)
	mw := io.MultiWriter(bw, dig)
	enc := json.NewEncoder(mw)
	if err := enc.Encode(postgresStateHeader{
		Format: postgresStateFormatTag, Version: postgresStateVersion,
		CreatedAt: time.Now().UTC(), Tables: tables, EventCutSequence: eventCut,
	}); err != nil {
		return PostgresStateSummary{}, err
	}

	summary := PostgresStateSummary{Tables: map[string]int{}, EventCutSequence: eventCut}
	for _, table := range tables {
		quotedTable, err := quoteBackupTable(table)
		if err != nil {
			return summary, err
		}
		rows, err := tx.Query(ctx, fmt.Sprintf(
			`SELECT to_jsonb(t)::jsonb
			   FROM (SELECT * FROM %s) AS t
			  ORDER BY to_jsonb(t)::text`,
			quotedTable))
		if err != nil {
			return summary, fmt.Errorf("backup: export %s: %w", table, err)
		}
		for rows.Next() {
			var row json.RawMessage
			if err := rows.Scan(&row); err != nil {
				rows.Close()
				return summary, fmt.Errorf("backup: scan %s: %w", table, err)
			}
			if err := enc.Encode(postgresStateRecord{Table: table, Row: row}); err != nil {
				rows.Close()
				return summary, err
			}
			summary.Tables[table]++
			summary.Records++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return summary, fmt.Errorf("backup: export %s rows: %w", table, err)
		}
		rows.Close()
	}
	tr := postgresStateTrailer{
		Format: postgresStateTrailerTag, SHA256: dig.sumHex(),
		Records: summary.Records, Tables: summary.Tables, EventCutSequence: eventCut,
	}
	if err := json.NewEncoder(bw).Encode(tr); err != nil {
		return summary, err
	}
	if err := bw.Flush(); err != nil {
		return summary, err
	}
	return summary, nil
}

// VerifyPostgresState reads and fully verifies an independent PostgreSQL state
// artifact without touching a store. Full restore uses this preflight to expose
// the paired event-log cut before it mutates NATS, PostgreSQL, or restored files.
func VerifyPostgresState(r io.Reader) (PostgresStateSummary, error) {
	_, summary, err := readVerifiedPostgresState(r)
	return summary, err
}

func readVerifiedPostgresState(r io.Reader) (map[string][]json.RawMessage, PostgresStateSummary, error) {
	h, rowsByTable, tr, err := readAndVerifyPostgresState(r)
	if err != nil {
		return nil, PostgresStateSummary{}, err
	}
	if h.Format != postgresStateFormatTag {
		return nil, PostgresStateSummary{}, fmt.Errorf("backup: not a trstctl postgres-state backup (format %q)", h.Format)
	}
	if h.Version != postgresStateVersion {
		return nil, PostgresStateSummary{}, fmt.Errorf("backup: unsupported postgres-state backup version %d (want %d)", h.Version, postgresStateVersion)
	}
	if h.EventCutSequence != tr.EventCutSequence {
		return nil, PostgresStateSummary{}, fmt.Errorf("backup: postgres-state integrity: header event cut %d but trailer event cut %d", h.EventCutSequence, tr.EventCutSequence)
	}
	if err := validatePostgresStateTables(h.Tables); err != nil {
		return nil, PostgresStateSummary{}, err
	}
	allowedTables := map[string]bool{}
	for _, table := range h.Tables {
		allowedTables[table] = true
	}
	for table := range rowsByTable {
		if !allowedTables[table] {
			return nil, PostgresStateSummary{}, fmt.Errorf("backup: postgres-state row names unclassified table %s", table)
		}
	}
	for table := range tr.Tables {
		if !allowedTables[table] {
			return nil, PostgresStateSummary{}, fmt.Errorf("backup: postgres-state trailer names unclassified table %s", table)
		}
	}
	summary := PostgresStateSummary{Tables: map[string]int{}, Records: tr.Records, EventCutSequence: tr.EventCutSequence}
	for table, rows := range rowsByTable {
		summary.Tables[table] = len(rows)
	}
	if summary.Records != sumTableCounts(summary.Tables) {
		return nil, PostgresStateSummary{}, fmt.Errorf("backup: postgres-state trailer claims %d records but tables contain %d", summary.Records, sumTableCounts(summary.Tables))
	}
	for table, count := range tr.Tables {
		if summary.Tables[table] != count {
			return nil, PostgresStateSummary{}, fmt.Errorf("backup: postgres-state trailer count for %s = %d but stream has %d", table, count, summary.Tables[table])
		}
	}
	checkpoints, err := latestAuditCheckpointBoundaries(rowsByTable["audit_checkpoints"])
	if err != nil {
		return nil, PostgresStateSummary{}, err
	}
	summary.AuditCheckpoints = checkpoints
	return rowsByTable, summary, nil
}

func latestAuditCheckpointBoundaries(rows []json.RawMessage) ([]AuditCheckpointBoundary, error) {
	latest := make(map[string]AuditCheckpointBoundary)
	for index, raw := range rows {
		var row struct {
			TenantID    string `json:"tenant_id"`
			BoundarySeq int64  `json:"boundary_seq"`
			RecordCount int64  `json:"record_count"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil, fmt.Errorf("backup: decode audit_checkpoints row %d: %w", index+1, err)
		}
		if row.TenantID == "" || row.BoundarySeq <= 0 || row.RecordCount <= 0 {
			return nil, fmt.Errorf("backup: audit_checkpoints row %d is incomplete", index+1)
		}
		candidate := AuditCheckpointBoundary{
			TenantID: row.TenantID, BoundarySeq: uint64(row.BoundarySeq),
			RecordCount: int(row.RecordCount),
		}
		if prior, ok := latest[row.TenantID]; !ok || candidate.BoundarySeq > prior.BoundarySeq {
			latest[row.TenantID] = candidate
		}
	}
	out := make([]AuditCheckpointBoundary, 0, len(latest))
	for _, checkpoint := range latest {
		out = append(out, checkpoint)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out, nil
}

// RestorePostgresState restores the independent PostgreSQL state artifact into a
// migrated database whose event-sourced read model has already been rebuilt once.
// The caller must run the private final event rebuild before serving: commands
// absent at the PostgreSQL cut intentionally remain detached until that replay.
func RestorePostgresState(ctx context.Context, st *store.Store, r io.Reader) (PostgresStateSummary, error) {
	rowsByTable, summary, err := readVerifiedPostgresState(r)
	if err != nil {
		return PostgresStateSummary{}, err
	}

	tx, err := st.SystemPool().Begin(ctx)
	if err != nil {
		return summary, fmt.Errorf("backup: begin postgres state restore: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Migration 0153 gives secret-sync outbox rows monotonic receiver-effect
	// authority that cannot be reconstructed from event replay. Its insert guard
	// accepts non-initial authority only inside this owner-role, transaction-local
	// restore window; the application role cannot turn this custom GUC into a forge
	// path.
	if _, err := tx.Exec(ctx, `SET LOCAL trstctl.postgres_state_restore = 'true'`); err != nil {
		return summary, fmt.Errorf("backup: mark postgres state restore transaction: %w", err)
	}
	// Snapshot blobs are an ephemeral copy of the read model and are never part
	// of this independent-state artifact. Remove them in the SAME restore
	// transaction so a migrated target cannot retain (or appear to import) a
	// pre-v22 payload containing a raw privacy-erased subject. The event log is
	// the source of truth and the snapshot worker will publish a fresh complete
	// all-tenant generation after recovery.
	if _, err := tx.Exec(ctx, `TRUNCATE TABLE read_model_snapshots`); err != nil {
		return summary, fmt.Errorf("backup: purge read-model snapshots before postgres state restore: %w", err)
	}

	// Match every restored secret-sync command to the first event-log rebuild by
	// stable command identity while both halves still exist. SQL allocation ids
	// may be reversed on the recovery host, so they are deliberately excluded
	// from this association decision.
	outboxRows, err := normalizePostgresStateRows("outbox", rowsByTable["outbox"])
	if err != nil {
		return summary, err
	}
	outboxRows, secretSyncAssociations, err := reconcileSecretSyncOutboxRows(ctx, tx, outboxRows)
	if err != nil {
		return summary, err
	}
	rowsByTable["outbox"] = outboxRows
	if err := detachSecretSyncJobsForOutboxRestore(ctx, tx); err != nil {
		return summary, err
	}

	truncateList, err := joinQuotedTables(postgresStateTables())
	if err != nil {
		return summary, err
	}
	if _, err := tx.Exec(ctx, "TRUNCATE "+truncateList+" CASCADE"); err != nil {
		return summary, fmt.Errorf("backup: clear postgres state tables: %w", err)
	}
	restoreOrder, err := postgresStateRestoreOrder()
	if err != nil {
		return summary, err
	}
	for _, table := range restoreOrder {
		rows := rowsByTable[table]
		if len(rows) == 0 {
			continue
		}
		if table != "outbox" {
			rows, err = normalizePostgresStateRows(table, rows)
			if err != nil {
				return summary, err
			}
		}
		payload, err := json.Marshal(rows)
		if err != nil {
			return summary, fmt.Errorf("backup: encode rows for %s: %w", table, err)
		}
		quotedTable, err := quoteBackupTable(table)
		if err != nil {
			return summary, err
		}
		q := fmt.Sprintf(
			`INSERT INTO %s OVERRIDING SYSTEM VALUE
			 SELECT * FROM jsonb_populate_recordset(NULL::%s, $1::jsonb)`,
			quotedTable, quotedTable)
		if _, err := tx.Exec(ctx, q, payload); err != nil {
			return summary, fmt.Errorf("backup: restore %s: %w", table, err)
		}
	}
	if err := reattachSecretSyncJobsAfterOutboxRestore(ctx, tx, secretSyncAssociations); err != nil {
		return summary, err
	}
	if _, err := tx.Exec(ctx,
		`SELECT setval(pg_get_serial_sequence('outbox', 'id'),
		        COALESCE((SELECT max(id) FROM outbox), 0) + 1,
		        false)`); err != nil {
		return summary, fmt.Errorf("backup: reset outbox identity: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return summary, fmt.Errorf("backup: commit postgres state restore: %w", err)
	}
	return summary, nil
}

// normalizePostgresStateRows upgrades rows from an older artifact to the
// current table shape after the artifact digest has been verified but before
// jsonb_populate_recordset types it. PostgreSQL fills a missing JSON field with
// NULL, not the column default. Fill only values whose historical meaning is
// deterministic; secret-sync authority is reconciled separately against rebuilt
// AN-2 state instead of being invented from a generic SQL row.
func normalizePostgresStateRows(table string, rows []json.RawMessage) ([]json.RawMessage, error) {
	if table == "outbox" {
		return normalizeLegacyNonSecretOutboxRows(rows)
	}
	if table != "idempotency_keys" {
		return rows, nil
	}
	normalized := make([]json.RawMessage, 0, len(rows))
	for index, raw := range rows {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, fmt.Errorf("backup: normalize idempotency_keys row %d: %w", index+1, err)
		}
		if fields == nil {
			return nil, fmt.Errorf("backup: normalize idempotency_keys row %d: row must be a JSON object", index+1)
		}
		codec, exists := fields["result_codec"]
		if !exists || bytes.Equal(bytes.TrimSpace(codec), []byte("null")) {
			encoded, err := json.Marshal("raw-v0")
			if err != nil {
				return nil, fmt.Errorf("backup: encode legacy idempotency result codec: %w", err)
			}
			fields["result_codec"] = encoded
		}
		encoded, err := json.Marshal(fields)
		if err != nil {
			return nil, fmt.Errorf("backup: encode normalized idempotency_keys row %d: %w", index+1, err)
		}
		normalized = append(normalized, encoded)
	}
	return normalized, nil
}

var secretSyncOutboxAuthorityFields = []string{
	"secret_sync_target_order",
	"secret_sync_order_from_event",
	"secret_sync_receiver_effect_state",
	"secret_sync_receiver_io_starts",
	"secret_sync_failure_detail",
	"secret_sync_failure_attempts",
}

// normalizeLegacyNonSecretOutboxRows supplies the neutral 0153 receiver tuple for
// old artifacts whose unrelated outbox rows predate those NOT NULL columns. A
// secret-sync row is deliberately left incomplete here: its causal order and
// receiver authority must be joined to the already-rebuilt command below.
func normalizeLegacyNonSecretOutboxRows(rows []json.RawMessage) ([]json.RawMessage, error) {
	normalized := make([]json.RawMessage, 0, len(rows))
	for index, raw := range rows {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, fmt.Errorf("backup: normalize outbox row %d: %w", index+1, err)
		}
		if fields == nil {
			return nil, fmt.Errorf("backup: normalize outbox row %d: row must be a JSON object", index+1)
		}
		var destination string
		if err := json.Unmarshal(fields["destination"], &destination); err != nil || destination == "" {
			return nil, fmt.Errorf("backup: normalize outbox row %d: destination is invalid", index+1)
		}
		if strings.HasPrefix(destination, "secret.sync.") {
			normalized = append(normalized, raw)
			continue
		}
		setDefault := func(name string, value any) error {
			if existing, ok := fields[name]; ok && !bytes.Equal(bytes.TrimSpace(existing), []byte("null")) {
				return nil
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				return err
			}
			fields[name] = encoded
			return nil
		}
		if err := setDefault("secret_sync_target_order", nil); err != nil {
			return nil, err
		}
		if err := setDefault("secret_sync_order_from_event", nil); err != nil {
			return nil, err
		}
		if err := setDefault("secret_sync_receiver_effect_state", "none"); err != nil {
			return nil, err
		}
		if err := setDefault("secret_sync_receiver_io_starts", 0); err != nil {
			return nil, err
		}
		if err := setDefault("secret_sync_failure_detail", ""); err != nil {
			return nil, err
		}
		if err := setDefault("secret_sync_failure_attempts", 0); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(fields)
		if err != nil {
			return nil, fmt.Errorf("backup: encode normalized outbox row %d: %w", index+1, err)
		}
		normalized = append(normalized, encoded)
	}
	return normalized, nil
}

type secretSyncOutboxRestoreAssociation struct {
	tenantID       string
	jobID          string
	idempotencyKey string
	destination    string
	payload        []byte
	targetOrder    int64
	orderFromEvent bool
}

// reconcileSecretSyncOutboxRows binds both current and pre-0153 artifact rows
// to the first event-log rebuild by tenant + receiver idempotency key + exact
// destination/payload/order. The artifact's SQL id is preserved for unrelated
// PostgreSQL references, but it is never used to decide which job owns the row.
// Missing/partial authority fails before any retained outbox row is replaced.
func reconcileSecretSyncOutboxRows(
	ctx context.Context,
	tx pgx.Tx,
	rows []json.RawMessage,
) ([]json.RawMessage, []secretSyncOutboxRestoreAssociation, error) {
	normalized := make([]json.RawMessage, 0, len(rows))
	associations := make([]secretSyncOutboxRestoreAssociation, 0)
	seenStableKeys := make(map[string]struct{})
	for index, raw := range rows {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, nil, fmt.Errorf("backup: reconcile outbox row %d: %w", index+1, err)
		}
		var row struct {
			ID                  int64           `json:"id"`
			TenantID            string          `json:"tenant_id"`
			Destination         string          `json:"destination"`
			EffectLane          string          `json:"effect_lane"`
			Payload             json.RawMessage `json:"payload"`
			IdempotencyKey      string          `json:"idempotency_key"`
			Status              string          `json:"status"`
			Attempts            int             `json:"attempts"`
			TargetOrder         *int64          `json:"secret_sync_target_order"`
			OrderFromEvent      *bool           `json:"secret_sync_order_from_event"`
			ReceiverEffectState *string         `json:"secret_sync_receiver_effect_state"`
			ReceiverIOStarts    *int64          `json:"secret_sync_receiver_io_starts"`
			FailureDetail       *string         `json:"secret_sync_failure_detail"`
			FailureAttempts     *int            `json:"secret_sync_failure_attempts"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil, nil, fmt.Errorf("backup: decode outbox row %d: %w", index+1, err)
		}
		if !strings.HasPrefix(row.Destination, "secret.sync.") {
			normalized = append(normalized, raw)
			continue
		}
		payload, err := decodePostgresJSONBytea(row.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("backup: decode secret-sync outbox row %d payload: %w", index+1, err)
		}
		if row.ID <= 0 || row.TenantID == "" || row.IdempotencyKey == "" ||
			len(payload) == 0 || row.Attempts < 0 {
			return nil, nil, fmt.Errorf("backup: secret-sync outbox row %d identity is incomplete", index+1)
		}
		stableKey := row.TenantID + "\x1f" + row.IdempotencyKey
		if _, duplicate := seenStableKeys[stableKey]; duplicate {
			return nil, nil, fmt.Errorf("backup: secret-sync outbox row %d duplicates a tenant receiver identity", index+1)
		}
		seenStableKeys[stableKey] = struct{}{}

		var rebuilt struct {
			jobID, target, remoteKey, requestBinding string
			targetOrder                              int64
			jobStatus                                string
			jobAttempts                              int
			lastError                                string
			terminalFromEvent                        *bool
			destination, effectLane, idempotencyKey  string
			payload                                  []byte
			outboxTargetOrder                        int64
			outboxOrderFromEvent                     bool
		}
		//trstctl:system-query — the cross-tenant system restore joins one tenant-scoped receiver key to its exact event-rebuilt job/outbox tuple before independent state is replaced (AN-1 exemption).
		err = tx.QueryRow(ctx, `
			SELECT job.id, job.target, job.remote_key, job.request_binding,
			       job.target_order, job.status, job.attempts, job.last_error,
			       job.terminal_event_from_event,
			       queued.destination, queued.effect_lane, queued.idempotency_key,
			       queued.payload, queued.secret_sync_target_order,
			       queued.secret_sync_order_from_event
			  FROM secret_sync_jobs AS job
			  JOIN outbox AS queued
			    ON queued.tenant_id = job.tenant_id
			   AND queued.id = job.outbox_id
			 WHERE job.tenant_id = $1
			   AND job.idempotency_key = $2
			 FOR KEY SHARE OF job, queued`, row.TenantID, row.IdempotencyKey).Scan(
			&rebuilt.jobID, &rebuilt.target, &rebuilt.remoteKey, &rebuilt.requestBinding,
			&rebuilt.targetOrder, &rebuilt.jobStatus, &rebuilt.jobAttempts, &rebuilt.lastError,
			&rebuilt.terminalFromEvent,
			&rebuilt.destination, &rebuilt.effectLane, &rebuilt.idempotencyKey,
			&rebuilt.payload, &rebuilt.outboxTargetOrder, &rebuilt.outboxOrderFromEvent,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, fmt.Errorf("backup: secret-sync outbox row %d has no exact rebuilt job/event authority", index+1)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("backup: reconcile secret-sync outbox row %d: %w", index+1, err)
		}
		expectedDestination := "secret.sync." + rebuilt.target
		expectedLane := "secret.sync:" + rebuilt.target
		if rebuilt.targetOrder == 0 || rebuilt.outboxTargetOrder != rebuilt.targetOrder ||
			rebuilt.destination != expectedDestination || rebuilt.effectLane != expectedLane ||
			rebuilt.idempotencyKey != row.IdempotencyKey ||
			row.Destination != expectedDestination ||
			(row.EffectLane != "" && row.EffectLane != expectedLane) ||
			!bytes.Equal(payload, rebuilt.payload) {
			return nil, nil, fmt.Errorf("backup: secret-sync outbox row %d differs from rebuilt command identity", index+1)
		}
		var binding struct {
			ID             string `json:"id"`
			Key            string `json:"key"`
			Target         string `json:"target"`
			RequestBinding string `json:"request_binding,omitempty"`
			Sealed         []byte `json:"sealed"`
		}
		if err := json.Unmarshal(payload, &binding); err != nil || binding.ID != rebuilt.jobID ||
			binding.Key != rebuilt.remoteKey || binding.Target != rebuilt.target ||
			binding.RequestBinding != rebuilt.requestBinding || len(binding.Sealed) == 0 {
			return nil, nil, fmt.Errorf("backup: secret-sync outbox row %d payload differs from rebuilt command identity", index+1)
		}
		associationTargetOrder := rebuilt.targetOrder
		associationOrderFromEvent := rebuilt.outboxOrderFromEvent
		reattachBeforeFinalRebuild := true
		present := 0
		for _, name := range secretSyncOutboxAuthorityFields {
			if value, ok := fields[name]; ok && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				present++
			}
		}
		if present == len(secretSyncOutboxAuthorityFields) {
			if row.TargetOrder == nil || row.OrderFromEvent == nil ||
				row.ReceiverEffectState == nil || row.ReceiverIOStarts == nil ||
				row.FailureDetail == nil || row.FailureAttempts == nil ||
				*row.TargetOrder == 0 ||
				(*row.OrderFromEvent && (*row.TargetOrder < 0 ||
					!rebuilt.outboxOrderFromEvent || *row.TargetOrder != rebuilt.targetOrder)) ||
				(!*row.OrderFromEvent && *row.TargetOrder > 0) {
				return nil, nil, fmt.Errorf("backup: secret-sync outbox row %d order authority differs from rebuilt command", index+1)
			}
			associationTargetOrder = *row.TargetOrder
			associationOrderFromEvent = *row.OrderFromEvent
			// A migration-derived negative order is PostgreSQL authority that an
			// event-only first rebuild cannot know. Import it now, leave the positive
			// temporary job detached, and let the private final rebuild reattach and
			// recreate the job with that exact negative order.
			reattachBeforeFinalRebuild = *row.TargetOrder == rebuilt.targetOrder &&
				*row.OrderFromEvent == rebuilt.outboxOrderFromEvent
		} else if present != 0 {
			return nil, nil, fmt.Errorf("backup: legacy secret-sync outbox row %d has partial receiver authority", index+1)
		} else {
			effectState := "none"
			receiverStarts := 0
			failureDetail := ""
			failureAttempts := 0
			switch rebuilt.jobStatus {
			case "pending":
				if row.Status != "pending" && row.Status != "processing" {
					return nil, nil, fmt.Errorf("backup: legacy secret-sync outbox row %d pending state differs from rebuilt job", index+1)
				}
				if row.Status == "processing" && row.Attempts == 0 {
					return nil, nil, fmt.Errorf("backup: legacy secret-sync outbox row %d processing state has no claim attempt", index+1)
				}
				if row.Attempts > 0 {
					effectState = "effect_possible"
					receiverStarts = row.Attempts
				}
			case "delivered":
				// A terminal event is projected before generic outbox finalization. Pending
				// or processing is therefore the recognized append/project-before-finalize
				// crash shape; the rebuilt terminal receipt makes resumed receiver I/O inert.
				if rebuilt.terminalFromEvent == nil || !*rebuilt.terminalFromEvent || rebuilt.jobAttempts < 1 ||
					(row.Status != "pending" && row.Status != "processing" && row.Status != "delivered") {
					return nil, nil, fmt.Errorf("backup: legacy secret-sync outbox row %d delivered state lacks rebuilt terminal authority", index+1)
				}
				effectState = "effect_possible"
				receiverStarts = max(row.Attempts, rebuilt.jobAttempts, 1)
			case "failed":
				if rebuilt.terminalFromEvent == nil || !*rebuilt.terminalFromEvent || rebuilt.jobAttempts < 1 || rebuilt.lastError == "" ||
					(row.Status != "pending" && row.Status != "processing" && row.Status != "failed" && row.Status != "delivered") {
					return nil, nil, fmt.Errorf("backup: legacy secret-sync outbox row %d failed state lacks rebuilt terminal authority", index+1)
				}
				// A pre-0153 artifact cannot prove whether the old generic failure
				// happened before or after receiver I/O. Keep every observed attempt
				// sticky and never manufacture current typed no-network authority.
				effectState = "effect_possible"
				receiverStarts = max(row.Attempts, rebuilt.jobAttempts, 1)
			default:
				return nil, nil, fmt.Errorf("backup: legacy secret-sync outbox row %d has invalid rebuilt job status %q", index+1, rebuilt.jobStatus)
			}

			set := func(name string, value any) error {
				encoded, err := json.Marshal(value)
				if err != nil {
					return err
				}
				fields[name] = encoded
				return nil
			}
			for name, value := range map[string]any{
				"secret_sync_target_order":          rebuilt.targetOrder,
				"secret_sync_order_from_event":      rebuilt.outboxOrderFromEvent,
				"secret_sync_receiver_effect_state": effectState,
				"secret_sync_receiver_io_starts":    receiverStarts,
				"secret_sync_failure_detail":        failureDetail,
				"secret_sync_failure_attempts":      failureAttempts,
			} {
				if err := set(name, value); err != nil {
					return nil, nil, fmt.Errorf("backup: encode legacy secret-sync outbox row %d field %s: %w", index+1, name, err)
				}
			}
		}
		encoded, err := json.Marshal(fields)
		if err != nil {
			return nil, nil, fmt.Errorf("backup: encode reconciled secret-sync outbox row %d: %w", index+1, err)
		}
		normalized = append(normalized, encoded)
		if reattachBeforeFinalRebuild {
			associations = append(associations, secretSyncOutboxRestoreAssociation{
				tenantID: row.TenantID, jobID: rebuilt.jobID,
				idempotencyKey: row.IdempotencyKey, destination: row.Destination,
				payload: append([]byte(nil), payload...), targetOrder: associationTargetOrder,
				orderFromEvent: associationOrderFromEvent,
			})
		}
	}
	return normalized, associations, nil
}

// decodePostgresJSONBytea decodes the exact text representation emitted by
// PostgreSQL's to_jsonb for a bytea column. It is hex prefixed with "\\x"; it is
// not encoding/json's base64 representation for a Go []byte. Keeping this
// decoder strict prevents an artifact from smuggling a second interpretation of
// the receiver command payload into restore-time authority matching.
func decodePostgresJSONBytea(raw json.RawMessage) ([]byte, error) {
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(encoded, `\x`) || len(encoded) <= 2 {
		return nil, errors.New("PostgreSQL bytea value is not nonempty hex")
	}
	decoded, err := hex.DecodeString(encoded[2:])
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("PostgreSQL bytea value has invalid hex")
	}
	return decoded, nil
}

// detachSecretSyncJobsForOutboxRestore removes SQL-id associations before the
// retained outbox table is replaced. Every job receives a unique negative
// transaction-local placeholder; the final event replay rebuilds jobs whose
// command was legitimately absent at the PostgreSQL backup cut.
func detachSecretSyncJobsForOutboxRestore(ctx context.Context, tx pgx.Tx) error {
	//trstctl:system-query — the cross-tenant system restore stages every tenant's event-derived secret-sync job before replacing the outbox artifact; no row data leaves PostgreSQL (AN-1 exemption).
	if _, err := tx.Exec(ctx, `
		WITH floor AS (
			SELECT LEAST(COALESCE(min(outbox_id), 0), 0) AS outbox_id
			  FROM secret_sync_jobs
		), staged AS (
			SELECT tenant_id, id,
			       floor.outbox_id - (row_number() OVER (ORDER BY tenant_id, id))::bigint AS outbox_id
			  FROM secret_sync_jobs
			 CROSS JOIN floor
		)
		UPDATE secret_sync_jobs AS job
		   SET outbox_id = staged.outbox_id
		  FROM staged
		 WHERE job.tenant_id = staged.tenant_id
		   AND job.id = staged.id`); err != nil {
		return fmt.Errorf("backup: detach rebuilt secret-sync jobs before outbox restore: %w", err)
	}
	return nil
}

func reattachSecretSyncJobsAfterOutboxRestore(
	ctx context.Context,
	tx pgx.Tx,
	associations []secretSyncOutboxRestoreAssociation,
) error {
	for index, association := range associations {
		var restoredOutboxID int64
		// Association is selected by the stable command tuple. queued.id is only
		// the value assigned after that match, never an input to the decision.
		err := tx.QueryRow(ctx, `
			UPDATE secret_sync_jobs AS job
			   SET outbox_id = queued.id
			  FROM outbox AS queued
			 WHERE job.tenant_id = $1
			   AND job.id = $2
			   AND job.outbox_id < 0
			   AND job.idempotency_key = $3
			   AND job.target_order = $6
			   AND queued.tenant_id = job.tenant_id
			   AND queued.idempotency_key = $3
			   AND queued.destination = $4
			   AND queued.destination = 'secret.sync.' || job.target
			   AND queued.payload = $5
			   AND queued.secret_sync_target_order = $6
			   AND queued.secret_sync_order_from_event = $7
			 RETURNING queued.id`,
			association.tenantID, association.jobID, association.idempotencyKey,
			association.destination, association.payload, association.targetOrder,
			association.orderFromEvent,
		).Scan(&restoredOutboxID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("backup: restored secret-sync association %d has no exact tenant/idempotency/destination/payload/order match", index+1)
		}
		if err != nil {
			return fmt.Errorf("backup: reattach restored secret-sync association %d: %w", index+1, err)
		}
		if restoredOutboxID <= 0 {
			return fmt.Errorf("backup: restored secret-sync association %d resolved an invalid outbox id", index+1)
		}
	}
	return nil
}

func readAndVerifyPostgresState(r io.Reader) (postgresStateHeader, map[string][]json.RawMessage, postgresStateTrailer, error) {
	var (
		h       postgresStateHeader
		tr      postgresStateTrailer
		haveHdr bool
		haveTr  bool
		records int
	)
	rowsByTable := map[string][]json.RawMessage{}
	dig := newDigest(nil)
	sc := bufio.NewScanner(bufio.NewReader(r))
	sc.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
	for sc.Scan() {
		if haveTr {
			return h, nil, tr, errors.New("backup: postgres-state integrity: data found after trailer")
		}
		line := sc.Bytes()
		var probe struct {
			Format string `json:"format"`
		}
		_ = json.Unmarshal(line, &probe)
		switch {
		case !haveHdr:
			if err := json.Unmarshal(line, &h); err != nil {
				return h, nil, tr, fmt.Errorf("backup: read postgres-state header: %w", err)
			}
			haveHdr = true
			feed(dig, line)
		case probe.Format == postgresStateTrailerTag:
			if err := json.Unmarshal(line, &tr); err != nil {
				return h, nil, tr, fmt.Errorf("backup: read postgres-state trailer: %w", err)
			}
			haveTr = true
		default:
			var rec postgresStateRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				return h, nil, tr, fmt.Errorf("backup: decode postgres-state record %d: %w", records+1, err)
			}
			rowsByTable[rec.Table] = append(rowsByTable[rec.Table], append(json.RawMessage(nil), rec.Row...))
			records++
			feed(dig, line)
		}
	}
	if err := sc.Err(); err != nil {
		return h, nil, tr, fmt.Errorf("backup: read postgres-state stream: %w", err)
	}
	if !haveHdr {
		return h, nil, tr, errors.New("backup: read postgres-state header: empty stream")
	}
	if !haveTr {
		return h, nil, tr, errors.New("backup: postgres-state integrity trailer missing; refusing to restore")
	}
	wantSum, err := hex.DecodeString(tr.SHA256)
	if err != nil || len(wantSum) == 0 {
		return h, nil, tr, errors.New("backup: postgres-state integrity: trailer has no valid sha256")
	}
	if !crypto.ConstantTimeEqual(dig.sum(), wantSum) {
		return h, nil, tr, errors.New("backup: postgres-state integrity check FAILED — corrupt or tampered backup")
	}
	if tr.Records != records {
		return h, nil, tr, fmt.Errorf("backup: postgres-state trailer claims %d records but stream has %d", tr.Records, records)
	}
	return h, rowsByTable, tr, nil
}

func validatePostgresStateTables(tables []string) error {
	got := append([]string(nil), tables...)
	want := postgresStateTables()
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		return fmt.Errorf("backup: postgres-state table manifest has %d tables, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			return fmt.Errorf("backup: postgres-state table manifest mismatch at %d: got %s want %s", i, got[i], want[i])
		}
	}
	return nil
}

func postgresStateTables() []string {
	out := append([]string(nil), RecoveredFromPostgresBackup...)
	sort.Strings(out)
	return out
}

func postgresStateRestoreOrder() ([]string, error) {
	parentFirst := []string{
		"api_tokens",
		"agent_bootstrap_tokens",
		// A3 redemptions reference outbox rows, but the outbox is a log-rebuilt
		// projection restored separately, and the reference is by id with no
		// foreign key — so ordering here is free. It restores beside the
		// bootstrap tokens because both are single-use ledgers whose whole
		// meaning is "this already happened once".
		"agent_job_credential_redemptions",
		// A1 receipts reference outbox rows by id with no foreign key, same as
		// the redemptions above, so ordering is free here too. It restores
		// beside them because the two together are the fabric's memory of what
		// agents were handed and what they reported back.
		"agent_job_receipts",
		// C3: no foreign keys, so ordering is free.
		"discovery_segments",
		"attestations",
		"audit_checkpoints",
		"credentials",
		"ct_log_checkpoints",
		"ct_watched_domains",
		// Restore the immutable revision before the current target row that names
		// it. Migration 0072 created legacy revisions without corresponding events.
		"deployment_target_revisions",
		"deployment_targets",
		"federation_peer_checkpoints",
		"idempotency_keys",
		"issuance_approval_requests",
		"issuance_approvals",
		"notification_routing_policies",
		"outbox",
		"policy_bindings",
		// The non-PII preparation is the durable cross-store crash bridge. It is
		// normally absent because capture refuses an active row, but classifying
		// and restoring it prevents an older/external artifact from silently
		// discarding the recovery instruction.
		"privacy_subject_erasure_preparations",
		"privacy_subject_erasure_operations",
		"secret_shares",
		"approved_target_event_fences",
		"application_secret_mutation_fences",
		"application_secret_tenant_epochs",
		// AUD-106: the fair-scan cursor is one bounded operational row per
		// tenant. Restore it with the exact due-edge commands so a recovered
		// scheduler continues the UUID ring instead of starving its tail again.
		"secret_rotation_schedule_scan_cursors",
		// AUD-113: restore the bound outer key above before its tick receiver
		// (composite FK), then restore the tick before child due-edge commands.
		// This preserves row_started recovery and exact terminal response bytes.
		"secret_rotation_schedule_ticks",
		// Child snapshot rows reference their parent tick and therefore restore
		// immediately after it, before any resumed due-edge command can inspect an
		// ordinal.
		"secret_rotation_schedule_tick_rows",
		// AUD-106: exact scheduled-rotation due-edge commands are independent
		// crash receivers. They deliberately have no FK to the rebuildable
		// schedule projection, so they can restore before that projection exists.
		"secret_rotation_schedule_commands",
		"secret_store",
		"secret_store_versions",
		"application_secret_mutation_receipts",
		"ssh_keys",
		"tenant_branding",
		"tenant_silos",
		// L2: provider billing meters. No foreign keys, so placement is free —
		// but they restore LAST on purpose: they are the provider's record of
		// what to invoice, and if a restore fails partway the absence of these
		// is obvious, whereas a half-restored meter would be silently short and
		// invoiced anyway.
		"provider_usage_meters",
		"provider_usage_coverage",
		// L2: per-customer quotas. No foreign keys; restored with the other
		// provider billing state. Losing this table fails OPEN (an uncapped
		// customer creates freely), so its restore must be as visible as the
		// meters': an obviously absent cap gets re-set, a silently absent one
		// gets discovered when the customer sails past it.
		"provider_tenant_quotas",
		// AUD-58: restore operator identities before their per-customer grants.
		// There is no FK, but this order prevents a partially inspected restore
		// from showing grants whose operator lifecycle has not arrived yet.
		"provider_operators",
		// L1: provider operator delegations. No foreign keys either, and it
		// restores after the meters for the same reason they restore last: this
		// is authority data, and a half-restored grant table is worse than an
		// obviously absent one — the plane fails closed on what is missing, so
		// a partial restore reads as a working plane that refuses some
		// operators rather than as an incomplete restore.
		"provider_operator_delegations",
		// L3: the provider tenant registry. No foreign key requires it, but the
		// registry restores before the break-glass ledger that scopes to its
		// tenants, and with the other provider authority data: a missing
		// customer list is obvious, a partial one is a provider quietly serving
		// fewer customers than they have.
		"provider_tenants",
		// L4: the break-glass grant ledger. Restores last among the provider
		// tables: it is consent history, and like the delegations above the
		// plane fails closed on whatever is missing — an absent grant reads as
		// "request again with two approvers", never as silent emergency access.
		"provider_breakglass_grants",
	}
	if err := validatePostgresStateRestoreOrder(parentFirst); err != nil {
		return nil, err
	}
	return parentFirst, nil
}

func validatePostgresStateRestoreOrder(order []string) error {
	for _, table := range order {
		if _, err := quoteBackupTable(table); err != nil {
			return fmt.Errorf("backup: postgres-state restore order invalid: %w", err)
		}
	}
	if err := validatePostgresStateTables(order); err != nil {
		return fmt.Errorf("backup: postgres-state restore order invalid: %w", err)
	}
	return nil
}

var backupTableNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

func quoteBackupTable(table string) (string, error) {
	if !backupTableNameRE.MatchString(table) {
		return "", fmt.Errorf("backup: unsafe table name in manifest: %s", table)
	}
	return `"` + table + `"`, nil
}

func joinQuotedTables(tables []string) (string, error) {
	out := make([]string, 0, len(tables))
	for _, table := range tables {
		quoted, err := quoteBackupTable(table)
		if err != nil {
			return "", err
		}
		out = append(out, quoted)
	}
	return stringsJoin(out, ", "), nil
}

func stringsJoin(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	n += len(sep) * (len(parts) - 1)
	b := make([]byte, 0, n)
	for i, p := range parts {
		if i > 0 {
			b = append(b, sep...)
		}
		b = append(b, p...)
	}
	return string(b)
}

func sumTableCounts(counts map[string]int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}
