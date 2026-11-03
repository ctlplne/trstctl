// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// The upgrade preflight (A246). The new binary runs it against the database
// before it migrates: what it would apply, what would stop it, and how the
// upgrade is undone. It changes nothing, and it carries names, versions, flags
// and times only — never a migration's SQL, a connection string or a row — so
// its report is safe to paste into a ticket.

// UpgradeFinding is one blocker or warning.
type UpgradeFinding struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// UpgradePendingMigration is one migration the upgrade would apply.
type UpgradePendingMigration struct {
	Version       int64  `json:"version"`
	Name          string `json:"name"`
	Destructive   bool   `json:"destructive"`
	Transactional bool   `json:"transactional"`
}

// UpgradeBackup is the backup a rollback would restore.
type UpgradeBackup struct {
	// Configured reports a backup directory (TRSTCTL_BACKUP_DIRECTORY).
	Configured bool `json:"configured"`
	// Verified reports the latest backup's bytes matching its manifest.
	Verified bool   `json:"verified"`
	TakenAt  string `json:"taken_at,omitempty"`
	// Fresh is a verified backup taken within backup.FreshFor.
	Fresh  bool   `json:"fresh"`
	Detail string `json:"detail,omitempty"`
}

// UpgradeRollback is how this upgrade is undone.
type UpgradeRollback struct {
	// Method is none (nothing to apply), rerun (a new database: a failed run
	// is continued by the next), redeploy_previous_binary (every pending
	// migration is additive) or restore_backup (one is not).
	Method string `json:"method"`
	Detail string `json:"detail"`
}

// UpgradePreflight is the verdict.
type UpgradePreflight struct {
	GeneratedAt        time.Time                 `json:"generated_at"`
	Ready              bool                      `json:"ready"`
	SchemaVersion      int64                     `json:"schema_version"`
	BinaryVersion      int64                     `json:"binary_version"`
	Pending            []UpgradePendingMigration `json:"pending"`
	ChecksumMismatches []string                  `json:"checksum_mismatches"`
	NewerThanBinary    []int64                   `json:"newer_than_binary"`
	InvalidIndexes     []string                  `json:"invalid_indexes"`
	LockHeld           bool                      `json:"lock_held"`
	Backup             UpgradeBackup             `json:"backup"`
	Blockers           []UpgradeFinding          `json:"blockers"`
	Warnings           []UpgradeFinding          `json:"warnings"`
	Rollback           UpgradeRollback           `json:"rollback"`
}

// EvaluateUpgradePreflight turns the database's position against this binary
// and the backup it would fall back on into the verdict.
func EvaluateUpgradePreflight(plan store.UpgradePlan, bk UpgradeBackup, now time.Time) UpgradePreflight {
	out := UpgradePreflight{
		GeneratedAt: now.UTC(), SchemaVersion: plan.SchemaVersion, BinaryVersion: plan.BinaryVersion,
		Pending:            []UpgradePendingMigration{},
		ChecksumMismatches: append([]string{}, plan.ChecksumMismatches...),
		NewerThanBinary:    append([]int64{}, plan.NewerThanBinary...),
		InvalidIndexes:     append([]string{}, plan.InvalidIndexes...),
		LockHeld:           plan.LockHeld, Backup: bk,
		Blockers: []UpgradeFinding{}, Warnings: []UpgradeFinding{},
	}
	var destructive, outside []string
	for _, m := range plan.Pending {
		out.Pending = append(out.Pending, UpgradePendingMigration{Version: m.Version, Name: m.Name, Destructive: m.Destructive, Transactional: m.Transactional})
		if m.Destructive {
			destructive = append(destructive, m.Name)
		}
		if !m.Transactional {
			outside = append(outside, m.Name)
		}
	}
	block := func(code, detail string) {
		out.Blockers = append(out.Blockers, UpgradeFinding{Code: code, Detail: detail})
	}
	warn := func(code, detail string) {
		out.Warnings = append(out.Warnings, UpgradeFinding{Code: code, Detail: detail})
	}
	fresh := plan.SchemaVersion == 0

	if len(plan.ChecksumMismatches) > 0 {
		block("checksum_mismatch", "applied migrations changed since they ran ("+strings.Join(plan.ChecksumMismatches, ", ")+"); the runner will not start until each is confirmed (docs/migrations.md, \"If a node refuses to start\")")
	}
	if plan.LockHeld {
		block("migration_running", "another run holds the migration lock: wait for it to finish, then run the preflight again")
	}
	if len(plan.NewerThanBinary) > 0 {
		warn("schema_newer_than_binary", fmt.Sprintf("a newer binary migrated this database (versions %v); this binary runs against it only because those migrations were additive", plan.NewerThanBinary))
	}
	if len(plan.InvalidIndexes) > 0 {
		warn("invalid_index", strings.Join(plan.InvalidIndexes, ", ")+" was left invalid by a failed concurrent build; the migration that builds it drops and rebuilds it, and any other must be dropped by hand")
	}
	if len(outside) > 0 && !fresh {
		warn("outside_transaction", strings.Join(outside, ", ")+" run outside a transaction: a failure keeps what they did so far, the next run completes them, and an index a failed build left is dropped at once")
	}

	switch {
	case len(plan.Pending) == 0:
		out.Rollback = UpgradeRollback{Method: "none", Detail: "this binary applies no migrations: rolling back is running the previous binary"}
	case fresh:
		out.Rollback = UpgradeRollback{Method: "rerun", Detail: "a new database: a failed run keeps the migrations before the failure, and the next run continues from there"}
	case len(destructive) == 0:
		out.Rollback = UpgradeRollback{Method: "redeploy_previous_binary", Detail: "every pending migration is additive: one that fails is undone or completed by the next run, and the previous binary runs against whatever was applied"}
		if !bk.Fresh {
			warn("no_fresh_backup", "no verified backup from the last 26 hours is visible: take one first (trstctl --full-backup-dir) so an unexpected failure still has a restore point")
		}
	default:
		out.Rollback = UpgradeRollback{Method: "restore_backup", Detail: "destructive: " + strings.Join(destructive, ", ") + ". Once applied, the previous binary may not find data it needs: rolling back is restoring the pre-upgrade backup (trstctl --full-restore-dir) and running the previous binary"}
		if !bk.Fresh {
			block("backup_required", "a pending migration cannot be undone by running the previous binary, and no verified backup from the last 26 hours is visible to restore: take one first (trstctl --full-backup-dir)")
		}
	}
	out.Ready = len(out.Blockers) == 0
	return out
}

// upgradeBackupState reads the configured backup directory's latest backup.
func upgradeBackupState(dir string, now time.Time) UpgradeBackup {
	if dir == "" {
		return UpgradeBackup{Detail: "no backup directory is configured (TRSTCTL_BACKUP_DIRECTORY), so a backup taken elsewhere is not visible here"}
	}
	report, err := backup.VerifyFullBackup(dir)
	if err != nil {
		return UpgradeBackup{Configured: true, Detail: "the configured backup directory holds no readable backup"}
	}
	out := UpgradeBackup{Configured: true, Verified: report.Verified}
	if !report.CreatedAt.IsZero() {
		out.TakenAt = report.CreatedAt.UTC().Format(time.RFC3339)
		out.Fresh = report.Verified && now.Sub(report.CreatedAt) <= backup.FreshFor
	}
	if !report.Verified {
		out.Detail = "the latest backup did not verify against its manifest"
	}
	return out
}

// RunUpgradePreflight reads where the database stands against this binary's
// migrations, core and every extension source, and the configured backup, and
// returns the verdict. It backs `trstctl --upgrade-preflight` and never
// migrates.
func RunUpgradePreflight(ctx context.Context, cfg *config.Config, extraMigrations []fs.FS, now time.Time) (UpgradePreflight, error) {
	if err := requireExternalPostgres(cfg); err != nil {
		return UpgradePreflight{}, err
	}
	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return UpgradePreflight{}, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	registerExtraMigrations(st, extraMigrations)
	plan, err := st.UpgradePlan(ctx)
	if err != nil {
		return UpgradePreflight{}, fmt.Errorf("read the upgrade plan: %w", err)
	}
	return EvaluateUpgradePreflight(plan, upgradeBackupState(cfg.Backup.Directory, now), now), nil
}

// WriteText prints the verdict for an operator.
func (p UpgradePreflight) WriteText(w io.Writer) {
	verdict := "ready"
	if !p.Ready {
		verdict = "not ready"
	}
	_, _ = fmt.Fprintf(w, "upgrade preflight: %s\n", verdict)
	_, _ = fmt.Fprintf(w, "schema version %d, this binary %d, %d migration(s) to apply\n", p.SchemaVersion, p.BinaryVersion, len(p.Pending))
	if p.SchemaVersion == 0 && len(p.Pending) > 0 {
		// A new database applies every migration; naming each is noise.
		_, _ = fmt.Fprintln(w, "  a new database: every migration applies")
	}
	for _, m := range p.Pending {
		if p.SchemaVersion == 0 {
			break
		}
		var notes []string
		if m.Destructive {
			notes = append(notes, "destructive")
		}
		if !m.Transactional {
			notes = append(notes, "outside a transaction")
		}
		if len(notes) > 0 {
			_, _ = fmt.Fprintf(w, "  %s (%s)\n", m.Name, strings.Join(notes, ", "))
		} else {
			_, _ = fmt.Fprintf(w, "  %s\n", m.Name)
		}
	}
	switch {
	case p.Backup.Fresh:
		_, _ = fmt.Fprintf(w, "backup: verified, taken %s\n", p.Backup.TakenAt)
	case p.Backup.TakenAt != "":
		_, _ = fmt.Fprintf(w, "backup: taken %s, verified %t, older than 26 hours or unverified\n", p.Backup.TakenAt, p.Backup.Verified)
	default:
		_, _ = fmt.Fprintf(w, "backup: %s\n", p.Backup.Detail)
	}
	_, _ = fmt.Fprintf(w, "rollback: %s — %s\n", p.Rollback.Method, p.Rollback.Detail)
	for _, f := range p.Blockers {
		_, _ = fmt.Fprintf(w, "blocker %s: %s\n", f.Code, f.Detail)
	}
	for _, f := range p.Warnings {
		_, _ = fmt.Fprintf(w, "warning %s: %s\n", f.Code, f.Detail)
	}
}

// failedUpgradeHint follows a failed migration: what state the database is in
// and the two ways on.
const failedUpgradeHint = "every migration before the failed one is applied and the failed one is not recorded: " +
	"start this binary again once the cause is fixed, or run the previous binary (docs/migrations.md, \"A failed upgrade\")"

// startupUpgradeAttrs are the log fields for the migrations a starting server
// is about to apply: how many, which are destructive or run outside a
// transaction, and how the upgrade is undone. Startup does not read the backup.
func startupUpgradeAttrs(plan store.UpgradePlan) []any {
	v := EvaluateUpgradePreflight(plan, UpgradeBackup{}, time.Now())
	attrs := []any{"count", len(v.Pending), "rollback", v.Rollback.Method}
	if plan.SchemaVersion == 0 {
		return attrs
	}
	var destructive, outside []string
	for _, m := range v.Pending {
		if m.Destructive {
			destructive = append(destructive, m.Name)
		}
		if !m.Transactional {
			outside = append(outside, m.Name)
		}
	}
	if len(destructive) > 0 {
		attrs = append(attrs, "destructive", destructive)
	}
	if len(outside) > 0 {
		attrs = append(attrs, "outside_transaction", outside)
	}
	return attrs
}
