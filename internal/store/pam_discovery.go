// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/pamdiscovery"
)

// ErrPAMDiscoverySourceNotFound is a discovery source that does not exist or
// was deleted.
var ErrPAMDiscoverySourceNotFound = errors.New("store: PAM discovery source not found")

// ErrPAMDiscoveryRunNotFound is a discovery run that does not exist.
var ErrPAMDiscoveryRunNotFound = errors.New("store: PAM discovery run not found")

// PAMDiscoverySource is a dynamic-secret provider whose target discovery
// scans (A260).
type PAMDiscoverySource struct {
	// TenantID is set only by the scheduler's cross-tenant list.
	TenantID        string
	ProviderID      string
	ProviderType    string
	IntervalSeconds int
	SavedBy         string
	SavedAt         time.Time
}

// PAMDiscoveryRun is one scan of a source.
type PAMDiscoveryRun struct {
	ID, ProviderID, Status, Failure string
	DeliveryStatus                  string
	StartedAt, FinishedAt           time.Time
	RequestedBy                     string
	Accounts, Added, Removed        int
	Changed                         int
	Changes                         []pamdiscovery.Change
}

// PAMDiscoveredAccount is a privileged account discovery has staged.
type PAMDiscoveredAccount struct {
	ID, ProviderID string
	Account        pamdiscovery.Account
	FirstSeenRun   string
	FirstSeenAt    time.Time
	LastSeenRun    string
	LastSeenAt     time.Time
	ChangedRun     string
	RemovedRun     string
	RemovedAt      *time.Time
	Status         string
}

// pamDiscoveredAccountID is an account's stable ID: the same on every replay.
func pamDiscoveredAccountID(tenantID, providerID, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("trstctl:pam-discovery:"+tenantID+"/"+providerID+"/"+key)).String()
}

// ApplyPAMDiscoverySourceSavedTx projects pam.discovery.source_saved.
func (s *Store) ApplyPAMDiscoverySourceSavedTx(ctx context.Context, tx pgx.Tx, tenantID string, src PAMDiscoverySource) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO pam_discovery_sources (tenant_id, provider_id, provider_type, interval_seconds, saved_by, saved_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, provider_id) DO UPDATE SET provider_type = EXCLUDED.provider_type,
		    interval_seconds = EXCLUDED.interval_seconds, saved_by = EXCLUDED.saved_by, saved_at = EXCLUDED.saved_at, deleted_at = NULL`,
		tenantID, src.ProviderID, src.ProviderType, src.IntervalSeconds, src.SavedBy, src.SavedAt.UTC())
	return err
}

// ApplyPAMDiscoverySourceDeletedTx projects pam.discovery.source_deleted.
// The source's runs and staged accounts stay.
func (s *Store) ApplyPAMDiscoverySourceDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, providerID string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_discovery_sources SET deleted_at = $3
		WHERE tenant_id = $1 AND provider_id = $2 AND deleted_at IS NULL`, tenantID, providerID, at.UTC())
	return err
}

// ApplyPAMDiscoveryRunTx projects pam.discovery.run_completed: the run, and
// for a completed one the difference from the source's staged accounts —
// accounts added, changed or no longer found — recorded as the run's
// changes. Replaying the same run changes nothing.
func (s *Store) ApplyPAMDiscoveryRunTx(ctx context.Context, tx pgx.Tx, tenantID string, run PAMDiscoveryRun, accounts []pamdiscovery.Account) error {
	if err := lockPAMDiscoverySourceTx(ctx, tx, tenantID, run.ProviderID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO pam_discovery_runs (tenant_id, id, provider_id, status, failure, started_at, finished_at, requested_by, accounts)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (tenant_id, id) DO UPDATE SET status=EXCLUDED.status,failure=EXCLUDED.failure,finished_at=EXCLUDED.finished_at,accounts=EXCLUDED.accounts
 WHERE pam_discovery_runs.tenant_id=$1 AND pam_discovery_runs.status='queued'
 AND pam_discovery_runs.provider_id=EXCLUDED.provider_id AND pam_discovery_runs.started_at=EXCLUDED.started_at`,
		tenantID, run.ID, run.ProviderID, run.Status, run.Failure, run.StartedAt.UTC(), run.FinishedAt.UTC(), run.RequestedBy, len(accounts))
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	// A live dispatcher acknowledges its own lease; source replay retires only
	// the recreated unclaimed operational intent.
	if _, err = tx.Exec(ctx, `UPDATE outbox SET status='delivered',delivered_at=COALESCE(delivered_at,$4),worker_id=NULL,lease_until=NULL
 WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3 AND status='pending' AND delivered_at IS NULL AND claimed_by_agent_id IS NULL AND worker_id IS NULL`, tenantID, pamdiscovery.ScanDestination, "pam-discovery:"+run.ID, run.FinishedAt); err != nil {
		return err
	}
	if run.Status != "completed" {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT account_key, name, kind, privileges, disabled, details FROM pam_discovered_accounts
		WHERE tenant_id = $1 AND provider_id = $2 AND removed_run IS NULL`, tenantID, run.ProviderID)
	if err != nil {
		return err
	}
	var previous []pamdiscovery.Account
	for rows.Next() {
		var a pamdiscovery.Account
		var privileges, details []byte
		if err := rows.Scan(&a.Key, &a.Name, &a.Kind, &privileges, &a.Disabled, &details); err != nil {
			rows.Close()
			return err
		}
		if err := json.Unmarshal(privileges, &a.Privileges); err != nil {
			rows.Close()
			return err
		}
		if err := json.Unmarshal(details, &a.Details); err != nil {
			rows.Close()
			return err
		}
		previous = append(previous, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	previous = pamdiscovery.Normalize(previous)
	changes := pamdiscovery.Diff(previous, accounts)
	counts := map[string]int{}
	for _, c := range changes {
		counts[c.Change]++
		raw, err := json.Marshal(c.Account)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO pam_discovery_run_changes (tenant_id, run_id, account_key, change, account)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, tenantID, run.ID, c.Account.Key, c.Change, raw); err != nil {
			return err
		}
		if c.Change == "removed" {
			if _, err := tx.Exec(ctx, `UPDATE pam_discovered_accounts SET removed_run = $4, removed_at = $5
				WHERE tenant_id = $1 AND provider_id = $2 AND account_key = $3`, tenantID, run.ProviderID, c.Account.Key, run.ID, run.FinishedAt.UTC()); err != nil {
				return err
			}
		}
	}
	changed := map[string]bool{}
	for _, c := range changes {
		if c.Change != "removed" {
			changed[c.Account.Key] = true
		}
	}
	for _, a := range accounts {
		privileges, err := json.Marshal(a.Privileges)
		if err != nil {
			return err
		}
		details, err := json.Marshal(a.Details)
		if err != nil {
			return err
		}
		if a.Details == nil {
			details = []byte("{}")
		}
		var changedRun any
		if changed[a.Key] {
			changedRun = run.ID
		}
		// A dismissed account found changed is staged again; an imported one
		// stays imported.
		if _, err := tx.Exec(ctx, `
			INSERT INTO pam_discovered_accounts AS cur (tenant_id, provider_id, account_key, id, name, kind, privileges, disabled, details,
			    first_seen_run, first_seen_at, last_seen_run, last_seen_at, changed_run)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $10, $11, $12)
			ON CONFLICT (tenant_id, provider_id, account_key) DO UPDATE SET
			    name = EXCLUDED.name, kind = EXCLUDED.kind, privileges = EXCLUDED.privileges, disabled = EXCLUDED.disabled,
			    details = EXCLUDED.details, last_seen_run = EXCLUDED.last_seen_run, last_seen_at = EXCLUDED.last_seen_at,
			    changed_run = COALESCE(EXCLUDED.changed_run, cur.changed_run), removed_run = NULL, removed_at = NULL,
			    status = CASE WHEN EXCLUDED.changed_run IS NOT NULL AND cur.status = 'dismissed' THEN 'staged' ELSE cur.status END`,
			tenantID, run.ProviderID, a.Key, pamDiscoveredAccountID(tenantID, run.ProviderID, a.Key), a.Name, a.Kind, privileges, a.Disabled,
			details, run.ID, run.FinishedAt.UTC(), changedRun); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE pam_discovery_runs SET added = $3, removed = $4, changed = $5 WHERE tenant_id = $1 AND id = $2`,
		tenantID, run.ID, counts["added"], counts["removed"], counts["changed"])
	return err
}

const pamDiscoveryRunColumns = `id::text, provider_id, status, failure, started_at, COALESCE(finished_at,'0001-01-01 00:00:00+00'::timestamptz), requested_by, accounts, added, removed, changed, COALESCE((SELECT o.status FROM outbox o WHERE o.tenant_id=$1 AND o.tenant_id=pam_discovery_runs.tenant_id AND o.id=pam_discovery_runs.outbox_id AND ((o.destination='pam.discovery.scan' AND o.idempotency_key='pam-discovery:'||pam_discovery_runs.id::text) OR (o.destination='host.windows_local_accounts.inventory' AND o.idempotency_key='windows-local-inventory:'||pam_discovery_runs.id::text))),'')`

func scanPAMDiscoveryRun(row pgx.Row) (PAMDiscoveryRun, error) {
	var r PAMDiscoveryRun
	err := row.Scan(&r.ID, &r.ProviderID, &r.Status, &r.Failure, &r.StartedAt, &r.FinishedAt, &r.RequestedBy, &r.Accounts, &r.Added,
		&r.Removed, &r.Changed, &r.DeliveryStatus)
	return r, err
}

// ListPAMDiscoverySources lists the tenant's live sources.
func (s *Store) ListPAMDiscoverySources(ctx context.Context, tenantID string) ([]PAMDiscoverySource, error) {
	var out []PAMDiscoverySource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT provider_id, provider_type, interval_seconds, saved_by, saved_at FROM pam_discovery_sources
			WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY provider_id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			src := PAMDiscoverySource{TenantID: tenantID}
			if err := rows.Scan(&src.ProviderID, &src.ProviderType, &src.IntervalSeconds, &src.SavedBy, &src.SavedAt); err != nil {
				return err
			}
			out = append(out, src)
		}
		return rows.Err()
	})
	return out, err
}

// GetPAMDiscoverySource returns a live source.
func (s *Store) GetPAMDiscoverySource(ctx context.Context, tenantID, providerID string) (PAMDiscoverySource, error) {
	src := PAMDiscoverySource{TenantID: tenantID}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT provider_id, provider_type, interval_seconds, saved_by, saved_at FROM pam_discovery_sources
			WHERE tenant_id = $1 AND provider_id = $2 AND deleted_at IS NULL`, tenantID, providerID).
			Scan(&src.ProviderID, &src.ProviderType, &src.IntervalSeconds, &src.SavedBy, &src.SavedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMDiscoverySource{}, ErrPAMDiscoverySourceNotFound
	}
	return src, err
}

// ScheduledPAMDiscoverySource is a source the scheduler scans, with when its
// last run finished (zero when it has none).
type ScheduledPAMDiscoverySource struct {
	PAMDiscoverySource
	LastFinishedAt time.Time
}

// ListScheduledPAMDiscoverySources lists every tenant's live sources that
// scan on an interval, with their last run's finish, for the scheduler.
func (s *Store) ListScheduledPAMDiscoverySources(ctx context.Context) ([]ScheduledPAMDiscoverySource, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — a cross-tenant read by design: the privileged account discovery scheduler lists every tenant's interval sources (tenant_id, provider, interval and last finish; no account data), and each scan and its event then run under that source's own tenant's RLS context.
		`SELECT s.tenant_id::text, s.provider_id, s.provider_type, s.interval_seconds, s.saved_by, s.saved_at,
		        COALESCE((SELECT max(r.finished_at) FROM pam_discovery_runs r WHERE r.tenant_id = s.tenant_id AND r.provider_id = s.provider_id), 'epoch'::timestamptz)
		   FROM pam_discovery_sources s WHERE s.deleted_at IS NULL AND s.interval_seconds > 0
		  ORDER BY s.tenant_id, s.provider_id LIMIT 10000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScheduledPAMDiscoverySource
	for rows.Next() {
		var src ScheduledPAMDiscoverySource
		if err := rows.Scan(&src.TenantID, &src.ProviderID, &src.ProviderType, &src.IntervalSeconds, &src.SavedBy, &src.SavedAt,
			&src.LastFinishedAt); err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

// ListPAMDiscoveryRuns lists the tenant's runs, newest first, optionally of
// one source.
func (s *Store) ListPAMDiscoveryRuns(ctx context.Context, tenantID, providerID string, limit int) ([]PAMDiscoveryRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	var out []PAMDiscoveryRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pamDiscoveryRunColumns+` FROM pam_discovery_runs
			WHERE tenant_id = $1 AND ($2 = '' OR provider_id = $2) ORDER BY started_at DESC, id LIMIT $3`, tenantID, providerID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanPAMDiscoveryRun(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// GetPAMDiscoveryRun returns a run with its changes.
func (s *Store) GetPAMDiscoveryRun(ctx context.Context, tenantID, id string) (PAMDiscoveryRun, error) {
	var run PAMDiscoveryRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		run, err = scanPAMDiscoveryRun(tx.QueryRow(ctx, `SELECT `+pamDiscoveryRunColumns+` FROM pam_discovery_runs
			WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT change, account FROM pam_discovery_run_changes WHERE tenant_id = $1 AND run_id = $2
			ORDER BY account_key`, tenantID, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c pamdiscovery.Change
			var raw []byte
			if err := rows.Scan(&c.Change, &raw); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &c.Account); err != nil {
				return err
			}
			run.Changes = append(run.Changes, c)
		}
		return rows.Err()
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMDiscoveryRun{}, ErrPAMDiscoveryRunNotFound
	}
	return run, err
}

// ListPAMDiscoveredAccounts lists the tenant's staged accounts, optionally of
// one source and status; removed ones only when asked.
func (s *Store) ListPAMDiscoveredAccounts(ctx context.Context, tenantID, providerID, status string, includeRemoved bool) ([]PAMDiscoveredAccount, error) {
	var out []PAMDiscoveredAccount
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, provider_id, account_key, name, kind, privileges, disabled, details,
		        first_seen_run::text, first_seen_at, last_seen_run::text, last_seen_at, COALESCE(changed_run::text, ''),
		        COALESCE(removed_run::text, ''), removed_at, status
		   FROM pam_discovered_accounts
		  WHERE tenant_id = $1 AND ($2 = '' OR provider_id = $2) AND ($3 = '' OR status = $3) AND ($4 OR removed_run IS NULL)
		  ORDER BY provider_id, account_key LIMIT 10000`, tenantID, providerID, status, includeRemoved)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a PAMDiscoveredAccount
			var privileges, details []byte
			if err := rows.Scan(&a.ID, &a.ProviderID, &a.Account.Key, &a.Account.Name, &a.Account.Kind, &privileges, &a.Account.Disabled,
				&details, &a.FirstSeenRun, &a.FirstSeenAt, &a.LastSeenRun, &a.LastSeenAt, &a.ChangedRun, &a.RemovedRun, &a.RemovedAt,
				&a.Status); err != nil {
				return err
			}
			if err := json.Unmarshal(privileges, &a.Account.Privileges); err != nil {
				return err
			}
			if err := json.Unmarshal(details, &a.Account.Details); err != nil {
				return err
			}
			if len(a.Account.Details) == 0 {
				a.Account.Details = nil
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// ErrPAMDiscoveredAccountNotFound is a staged account that does not exist.
var ErrPAMDiscoveredAccountNotFound = errors.New("store: discovered account not found")

// PAMDiscoveryImport is an approved import of staged accounts (A260 part 2).
type PAMDiscoveryImport struct {
	RequestID, ApprovalRequestID string
	Folder, TemplateID, Reason   string
	ImportedBy                   string
	ImportedAt                   time.Time
	Accounts                     []PAMImportedAccountRef
}

// PAMImportedAccountRef is one account an import names, as reviewed.
type PAMImportedAccountRef struct {
	ID, ProviderID, Key, Name, Kind string
	Privileges                      []string
}

// PAMImportedAccount is an account imported into a folder.
type PAMImportedAccount struct {
	PAMImportedAccountRef
	Folder, TemplateID, Reason   string
	RequestID, ApprovalRequestID string
	ImportedBy                   string
	ImportedAt                   time.Time
}

// ApplyPAMDiscoveryImportedTx projects pam.discovery.imported: each account
// is recorded in its folder and marked imported among the staged accounts.
// It changes nothing else. Replaying it changes nothing.
func (s *Store) ApplyPAMDiscoveryImportedTx(ctx context.Context, tx pgx.Tx, tenantID string, imp PAMDiscoveryImport) error {
	var template any
	if imp.TemplateID != "" {
		template = imp.TemplateID
	}
	for _, a := range imp.Accounts {
		privileges, err := json.Marshal(a.Privileges)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO pam_imported_accounts (tenant_id, provider_id, account_key, discovered_account_id, name, kind, privileges, folder,
			    template_id, reason, import_request_id, approval_request_id, imported_by, imported_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			ON CONFLICT (tenant_id, provider_id, account_key) DO NOTHING`,
			tenantID, a.ProviderID, a.Key, a.ID, a.Name, a.Kind, privileges, imp.Folder, template, imp.Reason, imp.RequestID,
			imp.ApprovalRequestID, imp.ImportedBy, imp.ImportedAt.UTC()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE pam_discovered_accounts SET status = 'imported'
			WHERE tenant_id = $1 AND provider_id = $2 AND account_key = $3`, tenantID, a.ProviderID, a.Key); err != nil {
			return err
		}
	}
	return nil
}

// ApplyPAMDiscoveryDismissedTx projects pam.discovery.dismissed: a staged
// account set aside with the reason, until a scan finds it changed.
func (s *Store) ApplyPAMDiscoveryDismissedTx(ctx context.Context, tx pgx.Tx, tenantID, providerID, key, reason, actor string) error {
	_, err := tx.Exec(ctx, `UPDATE pam_discovered_accounts SET status = 'dismissed', dismissed_reason = $4, dismissed_by = $5
		WHERE tenant_id = $1 AND provider_id = $2 AND account_key = $3 AND status = 'staged'`, tenantID, providerID, key, reason, actor)
	return err
}

// GetPAMDiscoveredAccount returns a staged account by its ID.
func (s *Store) GetPAMDiscoveredAccount(ctx context.Context, tenantID, id string) (PAMDiscoveredAccount, error) {
	var a PAMDiscoveredAccount
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var privileges, details []byte
		err := tx.QueryRow(ctx, `SELECT id::text, provider_id, account_key, name, kind, privileges, disabled, details,
		        first_seen_run::text, first_seen_at, last_seen_run::text, last_seen_at, COALESCE(changed_run::text, ''),
		        COALESCE(removed_run::text, ''), removed_at, status
		   FROM pam_discovered_accounts WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&a.ID, &a.ProviderID, &a.Account.Key, &a.Account.Name, &a.Account.Kind, &privileges, &a.Account.Disabled, &details,
				&a.FirstSeenRun, &a.FirstSeenAt, &a.LastSeenRun, &a.LastSeenAt, &a.ChangedRun, &a.RemovedRun, &a.RemovedAt, &a.Status)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(privileges, &a.Account.Privileges); err != nil {
			return err
		}
		return json.Unmarshal(details, &a.Account.Details)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMDiscoveredAccount{}, ErrPAMDiscoveredAccountNotFound
	}
	return a, err
}

// ListPAMImportedAccounts lists the tenant's imported accounts, optionally of
// one folder or source.
func (s *Store) ListPAMImportedAccounts(ctx context.Context, tenantID, folder, providerID string) ([]PAMImportedAccount, error) {
	var out []PAMImportedAccount
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT discovered_account_id::text, provider_id, account_key, name, kind, privileges, folder,
		        COALESCE(template_id::text, ''), reason, import_request_id::text, approval_request_id::text, imported_by, imported_at
		   FROM pam_imported_accounts
		  WHERE tenant_id = $1 AND ($2 = '' OR folder = $2) AND ($3 = '' OR provider_id = $3)
		  ORDER BY folder, provider_id, account_key LIMIT 10000`, tenantID, folder, providerID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a PAMImportedAccount
			var privileges []byte
			if err := rows.Scan(&a.ID, &a.ProviderID, &a.Key, &a.Name, &a.Kind, &privileges, &a.Folder, &a.TemplateID, &a.Reason,
				&a.RequestID, &a.ApprovalRequestID, &a.ImportedBy, &a.ImportedAt); err != nil {
				return err
			}
			if err := json.Unmarshal(privileges, &a.Privileges); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
