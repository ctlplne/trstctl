package backup

import (
	"bufio"
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
	Format    string    `json:"format"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Tables    []string  `json:"tables"`
}

type postgresStateRecord struct {
	Table string          `json:"table"`
	Row   json.RawMessage `json:"row"`
}

type postgresStateTrailer struct {
	Format  string         `json:"format"`
	SHA256  string         `json:"sha256"`
	Records int            `json:"records"`
	Tables  map[string]int `json:"tables"`
}

// PostgresStateSummary reports the row counts written or restored for the
// independent PostgreSQL state artifact.
type PostgresStateSummary struct {
	Tables  map[string]int `json:"tables"`
	Records int            `json:"records"`
}

// WritePostgresState writes all independent PostgreSQL state classified in the
// backup manifest to w as JSONL with an integrity trailer. Projection/read-model
// tables are intentionally excluded: the event log restores those.
func WritePostgresState(ctx context.Context, st *store.Store, w io.Writer) (PostgresStateSummary, error) {
	tables := postgresStateTables()
	bw := bufio.NewWriter(w)
	dig := newDigest(nil)
	mw := io.MultiWriter(bw, dig)
	enc := json.NewEncoder(mw)
	if err := enc.Encode(postgresStateHeader{
		Format: postgresStateFormatTag, Version: postgresStateVersion,
		CreatedAt: time.Now().UTC(), Tables: tables,
	}); err != nil {
		return PostgresStateSummary{}, err
	}

	tx, err := st.SystemPool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return PostgresStateSummary{}, fmt.Errorf("backup: begin postgres state export: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	summary := PostgresStateSummary{Tables: map[string]int{}}
	for _, table := range tables {
		rows, err := tx.Query(ctx, fmt.Sprintf(
			`SELECT to_jsonb(t)::jsonb
			   FROM (SELECT * FROM %s) AS t
			  ORDER BY to_jsonb(t)::text`,
			quoteBackupTable(table)))
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
	if err := tx.Commit(ctx); err != nil {
		return summary, fmt.Errorf("backup: finish postgres state export: %w", err)
	}

	tr := postgresStateTrailer{
		Format: postgresStateTrailerTag, SHA256: dig.sumHex(),
		Records: summary.Records, Tables: summary.Tables,
	}
	if err := json.NewEncoder(bw).Encode(tr); err != nil {
		return summary, err
	}
	if err := bw.Flush(); err != nil {
		return summary, err
	}
	return summary, nil
}

// RestorePostgresState restores the independent PostgreSQL state artifact into a
// migrated database whose event-sourced read model has already been rebuilt.
func RestorePostgresState(ctx context.Context, st *store.Store, r io.Reader) (PostgresStateSummary, error) {
	h, rowsByTable, tr, err := readAndVerifyPostgresState(r)
	if err != nil {
		return PostgresStateSummary{}, err
	}
	if h.Format != postgresStateFormatTag {
		return PostgresStateSummary{}, fmt.Errorf("backup: not a trstctl postgres-state backup (format %q)", h.Format)
	}
	if h.Version != postgresStateVersion {
		return PostgresStateSummary{}, fmt.Errorf("backup: unsupported postgres-state backup version %d (want %d)", h.Version, postgresStateVersion)
	}
	if err := validatePostgresStateTables(h.Tables); err != nil {
		return PostgresStateSummary{}, err
	}
	allowedTables := map[string]bool{}
	for _, table := range h.Tables {
		allowedTables[table] = true
	}
	for table := range rowsByTable {
		if !allowedTables[table] {
			return PostgresStateSummary{}, fmt.Errorf("backup: postgres-state row names unclassified table %s", table)
		}
	}
	for table := range tr.Tables {
		if !allowedTables[table] {
			return PostgresStateSummary{}, fmt.Errorf("backup: postgres-state trailer names unclassified table %s", table)
		}
	}
	summary := PostgresStateSummary{Tables: map[string]int{}, Records: tr.Records}
	for table, rows := range rowsByTable {
		summary.Tables[table] = len(rows)
	}
	if summary.Records != sumTableCounts(summary.Tables) {
		return PostgresStateSummary{}, fmt.Errorf("backup: postgres-state trailer claims %d records but tables contain %d", summary.Records, sumTableCounts(summary.Tables))
	}
	for table, count := range tr.Tables {
		if summary.Tables[table] != count {
			return PostgresStateSummary{}, fmt.Errorf("backup: postgres-state trailer count for %s = %d but stream has %d", table, count, summary.Tables[table])
		}
	}

	tx, err := st.SystemPool().Begin(ctx)
	if err != nil {
		return summary, fmt.Errorf("backup: begin postgres state restore: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "TRUNCATE "+joinQuotedTables(postgresStateTables())); err != nil {
		return summary, fmt.Errorf("backup: clear postgres state tables: %w", err)
	}
	for _, table := range postgresStateRestoreOrder() {
		rows := rowsByTable[table]
		if len(rows) == 0 {
			continue
		}
		payload, err := json.Marshal(rows)
		if err != nil {
			return summary, fmt.Errorf("backup: encode rows for %s: %w", table, err)
		}
		q := fmt.Sprintf(
			`INSERT INTO %s OVERRIDING SYSTEM VALUE
			 SELECT * FROM jsonb_populate_recordset(NULL::%s, $1::jsonb)`,
			quoteBackupTable(table), quoteBackupTable(table))
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

func postgresStateRestoreOrder() []string {
	parentFirst := []string{
		"api_tokens",
		"agent_bootstrap_tokens",
		"attestations",
		"audit_checkpoints",
		"ca_authorities",
		"ca_key_ceremonies",
		"ca_ceremony_approvals",
		"ca_crls",
		"ca_issued_certs",
		"certificate_profiles",
		"credentials",
		"crypto_assets",
		"ct_log_checkpoints",
		"ct_watched_domains",
		"deployment_targets",
		"idempotency_keys",
		"issuance_approval_requests",
		"issuance_approvals",
		"outbox",
		"policy_bindings",
		"secret_store",
		"ssh_keys",
	}
	if err := validatePostgresStateTables(parentFirst); err != nil {
		panic(err)
	}
	return parentFirst
}

var backupTableNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

func quoteBackupTable(table string) string {
	if !backupTableNameRE.MatchString(table) {
		panic("backup: unsafe table name in manifest: " + table)
	}
	return `"` + table + `"`
}

func joinQuotedTables(tables []string) string {
	out := make([]string, 0, len(tables))
	for _, table := range tables {
		out = append(out, quoteBackupTable(table))
	}
	return stringsJoin(out, ", ")
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
