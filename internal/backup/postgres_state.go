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
func BeginPostgresStateSnapshot(ctx context.Context, st *store.Store) (pgx.Tx, error) {
	tx, err := st.SystemPool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("backup: begin postgres state snapshot: %w", err)
	}
	var pinned int
	if err := tx.QueryRow(ctx, `SELECT 1`).Scan(&pinned); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("backup: pin postgres state snapshot: %w", err)
	}
	return tx, nil
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

// WritePostgresStateTx writes PostgreSQL state from the caller's read-only
// repeatable-read transaction. Full backup uses a transaction pinned under the
// backup write fence, paired with the event-log cut in the artifact header.
func WritePostgresStateTx(ctx context.Context, tx pgx.Tx, w io.Writer, eventCut uint64) (PostgresStateSummary, error) {
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
// migrated database whose event-sourced read model has already been rebuilt.
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
		rows, err = normalizePostgresStateRows(table, rows)
		if err != nil {
			return summary, err
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
// NULL, not the column default, so a pre-result_codec idempotency row would
// otherwise violate the new NOT NULL wall during restore.
func normalizePostgresStateRows(table string, rows []json.RawMessage) ([]json.RawMessage, error) {
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
		"privacy_subject_erasure_operations",
		"secret_shares",
		"secret_store",
		"secret_store_versions",
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
		// L1: provider operator delegations. No foreign keys either, and it
		// restores after the meters for the same reason they restore last: this
		// is authority data, and a half-restored grant table is worse than an
		// obviously absent one — the plane fails closed on what is missing, so
		// a partial restore reads as a working plane that refuses some
		// operators rather than as an incomplete restore.
		"provider_operator_delegations",
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
