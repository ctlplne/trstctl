// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
)

const discoveryRunDiagnosticPrivacySelector = "discovery_run_diagnostics"

type discoveryRunPrivacyMatch struct {
	record      PrivacyReadModelRecord
	requester   bool
	diagnostics []PrivacyReadModelSelector
}

// A run completion's target order is immutable. Address one diagnostic by
// run and position so the erasure selector never has to carry a raw target.
func discoveryRunTargetErrorID(runID string, position int) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("discovery-target-error:"+runID+":"+strconv.Itoa(position))).String()
}

func selectDiscoveryRunPrivacy(ctx context.Context, tx pgx.Tx, tenantID, subject string, includeData bool) ([]discoveryRunPrivacyMatch, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text, source_id::text, created_at, requested_by = $2,
		       CASE WHEN diagnostics_classified THEN error ELSE '' END,
		       CASE WHEN diagnostics_classified THEN target_results ELSE '[]'::jsonb END,
		       CASE WHEN $3::boolean THEN jsonb_build_object(
		           'status', status, 'dry_run', dry_run, 'requested_by', requested_by, 'targets', targets,
		           'discovered', discovered, 'failed', failed, 'rejected', rejected, 'started_at', started_at, 'completed_at', completed_at,
		           'error', CASE WHEN diagnostics_classified THEN error ELSE '' END,
		           'target_results', CASE WHEN diagnostics_classified THEN target_results ELSE '[]'::jsonb END)::text
		           ELSE '' END
		  FROM discovery_runs
		 WHERE tenant_id = $1 AND (requested_by = $2 OR
		       (diagnostics_classified AND (position($2 in error) > 0 OR EXISTS (
		           SELECT 1 FROM jsonb_array_elements(target_results) AS outcome WHERE position($2 in (outcome->>'error')) > 0))))
		 ORDER BY id`, tenantID, subject, includeData)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []discoveryRunPrivacyMatch
	for rows.Next() {
		match := discoveryRunPrivacyMatch{record: PrivacyReadModelRecord{Table: "discovery_runs"}}
		var detail string
		var targetJSON []byte
		r := &match.record
		if err := rows.Scan(&r.ID, &r.ParentID, &r.At, &match.requester, &detail, &targetJSON, &r.Data); err != nil {
			return nil, err
		}
		if events.PrivacyFreeTextContainsSubject(detail, subject) {
			match.diagnostics = append(match.diagnostics, PrivacyReadModelSelector{Table: discoveryRunDiagnosticPrivacySelector, ID: r.ID})
		}
		var targets []DiscoveryTargetResult
		if err := json.Unmarshal(targetJSON, &targets); err != nil {
			return nil, err
		}
		for i, target := range targets {
			if events.PrivacyFreeTextContainsSubject(target.Error, subject) {
				match.diagnostics = append(match.diagnostics, PrivacyReadModelSelector{
					Table: discoveryRunDiagnosticPrivacySelector, ID: r.ID, ParentID: discoveryRunTargetErrorID(r.ID, i),
				})
			}
		}
		if match.requester || len(match.diagnostics) > 0 {
			result = append(result, match)
		}
	}
	return result, rows.Err()
}

func eraseDiscoveryRunDiagnosticPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, discoveryRunDiagnosticPrivacySelector)
	if len(ids) == 0 {
		return nil
	}
	selected := make(map[string]map[string]bool, len(ids))
	for _, id := range ids {
		selected[id] = make(map[string]bool)
	}
	for _, selector := range selectors {
		if fields, ok := selected[selector.ID]; selector.Table == discoveryRunDiagnosticPrivacySelector && ok {
			fields[selector.ParentID] = true
		}
	}
	rows, err := tx.Query(ctx, `SELECT id::text, error, target_results FROM discovery_runs
		WHERE tenant_id = $1 AND id::text = ANY($2) AND diagnostics_classified FOR UPDATE`, tenantID, ids)
	if err != nil {
		return err
	}
	type runDiagnostics struct {
		id, detail string
		targets    []byte
	}
	var matched []runDiagnostics
	for rows.Next() {
		var run runDiagnostics
		if err := rows.Scan(&run.id, &run.detail, &run.targets); err != nil {
			rows.Close()
			return err
		}
		matched = append(matched, run)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, run := range matched {
		fields := selected[run.id]
		if fields[""] {
			run.detail = ""
		}
		var targets []DiscoveryTargetResult
		if err := json.Unmarshal(run.targets, &targets); err != nil {
			return err
		}
		for i := range targets {
			if fields[discoveryRunTargetErrorID(run.id, i)] {
				targets[i].Error = ""
			}
		}
		data, err := json.Marshal(targets)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE discovery_runs SET error = $3, target_results = $4
			WHERE tenant_id = $1 AND id::text = $2`, tenantID, run.id, run.detail, data); err != nil {
			return err
		}
	}
	return nil
}
