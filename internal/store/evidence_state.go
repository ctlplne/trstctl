// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Evidence report current state (A252): the counts an evidence report reads at
// render time, beside the window of events it replays. Totals come first, so a
// zero is reported as a zero rather than left out. Every query is a count
// under the tenant's RLS that returns (name, count) pairs; none returns a row's
// contents. Status-derived names come from closed status columns.

type evidenceStateQuery struct {
	sql     string
	usesNow bool // the query takes now as $2
}

var evidenceStateQueries = map[string][]evidenceStateQuery{
	"lifecycle_evidence": {
		{sql: `SELECT 'certificates', count(*)::integer FROM certificates WHERE tenant_id = $1`},
		{sql: `SELECT 'certificates_expiring_within_30_days', count(*)::integer FROM certificates
			WHERE tenant_id = $1 AND not_after >= $2 AND not_after < $2 + interval '30 days'`, usesNow: true},
		{sql: `SELECT 'certificates_without_owner', count(*)::integer FROM certificates WHERE tenant_id = $1 AND owner_id IS NULL`},
		{sql: `SELECT 'identities', count(*)::integer FROM identities WHERE tenant_id = $1`},
		{sql: `SELECT 'identities_' || status, count(*)::integer FROM identities WHERE tenant_id = $1 GROUP BY status`},
	},
	"access_evidence": {
		{sql: `SELECT 'members', count(*)::integer FROM tenant_members WHERE tenant_id = $1`},
		{sql: `SELECT 'members_' || status, count(*)::integer FROM tenant_members WHERE tenant_id = $1 GROUP BY status`},
		{sql: `SELECT 'api_tokens_active', count(*)::integer FROM api_tokens
			WHERE tenant_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $2)`, usesNow: true},
		{sql: `SELECT 'pam_sessions', count(*)::integer FROM pam_sessions WHERE tenant_id = $1`},
		{sql: `SELECT 'pam_sessions_' || status, count(*)::integer FROM pam_sessions WHERE tenant_id = $1 GROUP BY status`},
		{sql: `SELECT 'access_bundles_live', count(*)::integer FROM access_bundles WHERE tenant_id = $1 AND deleted_at IS NULL`},
		{sql: `SELECT 'access_bundle_grants_unremoved', count(*)::integer FROM access_bundle_grants
			WHERE tenant_id = $1 AND removed_at IS NULL AND (expires_at IS NULL OR expires_at > $2)`, usesNow: true},
		{sql: `SELECT 'access_bundle_runs_active', count(*)::integer FROM access_bundle_runs
			WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > $2`, usesNow: true},
	},
	"rotation_evidence": {
		{sql: `SELECT 'secret_rotation_schedules_enabled', count(*)::integer FROM secret_rotation_schedules WHERE tenant_id = $1 AND enabled`},
		{sql: `SELECT 'secret_rotation_schedules_overdue', count(*)::integer FROM secret_rotation_schedules
			WHERE tenant_id = $1 AND enabled AND next_run_at < $2`, usesNow: true},
		{sql: `SELECT 'secret_rotation_last_run_' || last_run_status, count(*)::integer FROM secret_rotation_schedules
			WHERE tenant_id = $1 AND last_run_status <> '' GROUP BY last_run_status`},
	},
	"incident_response_evidence": {
		{sql: `SELECT 'incident_executions', count(*)::integer FROM incident_executions WHERE tenant_id = $1`},
		{sql: `SELECT 'incident_executions_' || status, count(*)::integer FROM incident_executions WHERE tenant_id = $1 GROUP BY status`},
	},
	"qualification_evidence": {
		{sql: `SELECT 'rehearsal_scenarios', count(*)::integer FROM rehearsal_scenarios WHERE tenant_id = $1`},
		{sql: `SELECT 'rehearsal_runs', count(*)::integer FROM rehearsal_runs WHERE tenant_id = $1`},
		{sql: `SELECT 'rehearsal_runs_' || verdict, count(*)::integer FROM rehearsal_runs
			WHERE tenant_id = $1 AND status = 'completed' AND verdict <> '' GROUP BY verdict`},
	},
}

// EvidenceCurrentState returns the named counts one evidence report kind reads
// at now.
func (s *Store) EvidenceCurrentState(ctx context.Context, tenantID, kind string, now time.Time) (map[string]int, error) {
	queries, ok := evidenceStateQueries[kind]
	if !ok {
		return nil, fmt.Errorf("store: unknown evidence report kind %q", kind)
	}
	out := map[string]int{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, q := range queries {
			args := []any{tenantID}
			if q.usesNow {
				args = append(args, now.UTC())
			}
			rows, err := tx.Query(ctx, q.sql, args...)
			if err != nil {
				return err
			}
			for rows.Next() {
				var name string
				var n int
				if err := rows.Scan(&name, &n); err != nil {
					rows.Close()
					return err
				}
				out[name] = n
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}
