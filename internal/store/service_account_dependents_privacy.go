// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"github.com/jackc/pgx/v5"
	"time"
)

func privacyReadModelExportQueries(tenantID, subject string) []privacyReadModelQuery {
	return append(basePrivacyReadModelExportQueries(tenantID, subject),
		privacyReadModelQuery{table: "service_account_rotation_manifests", sql: `SELECT id::text,id::text,to_jsonb(r)::text,created_at FROM service_account_rotation_manifests r WHERE tenant_id=$1 AND actor=$2 ORDER BY id`, args: []any{tenantID, subject}},
		privacyReadModelQuery{table: "service_account_rotations", sql: `SELECT id::text,command_id::text,to_jsonb(r)::text,created_at FROM service_account_rotations r WHERE tenant_id=$1 AND actor=$2 ORDER BY id`, args: []any{tenantID, subject}},
		privacyReadModelQuery{table: "service_account_hosts", sql: `SELECT agent_id::text,account_id::text,to_jsonb(h)::text,updated_at FROM service_account_hosts h WHERE tenant_id=$1 AND saved_by=$2 ORDER BY account_id,agent_id`, args: []any{tenantID, subject}},
		privacyReadModelQuery{table: "service_account_host_scans", sql: `SELECT id::text,account_id::text,to_jsonb(s)::text,queued_at FROM service_account_host_scans s WHERE tenant_id=$1 AND queued_by=$2 ORDER BY id`, args: []any{tenantID, subject}})
}
func privacyReadModelSelectorQueries(tenantID, subject string) []privacyReadModelQuery {
	return append(basePrivacyReadModelSelectorQueries(tenantID, subject),
		privacyReadModelQuery{table: "service_account_rotation_manifests", sql: `SELECT id::text,id::text,0 FROM service_account_rotation_manifests WHERE tenant_id=$1 AND actor=$2 ORDER BY id`, args: []any{tenantID, subject}},
		privacyReadModelQuery{table: "service_account_rotations", sql: `SELECT id::text,command_id::text,0 FROM service_account_rotations WHERE tenant_id=$1 AND actor=$2 ORDER BY id`, args: []any{tenantID, subject}},
		privacyReadModelQuery{table: "service_account_hosts", sql: `SELECT agent_id::text,account_id::text,0 FROM service_account_hosts WHERE tenant_id=$1 AND saved_by=$2 ORDER BY account_id,agent_id`, args: []any{tenantID, subject}},
		privacyReadModelQuery{table: "service_account_host_scans", sql: `SELECT id::text,account_id::text,0 FROM service_account_host_scans WHERE tenant_id=$1 AND queued_by=$2 ORDER BY id`, args: []any{tenantID, subject}})
}
func eraseServiceDependentActorPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	for _, selector := range selectors {
		var actor string
		switch selector.Table {
		case "service_account_rotation_manifests":
			err := tx.QueryRow(ctx, `SELECT actor FROM service_account_rotation_manifests WHERE tenant_id=$1 AND id::text=$2 AND id::text=$3 FOR UPDATE`, tenantID, selector.ID, selector.ParentID).Scan(&actor)
			if err == pgx.ErrNoRows {
				continue
			}
			if err != nil {
				return err
			}
			if !subjectValueMatches(tenantID, subjectRef, actor) {
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE service_account_rotation_manifests SET actor=$4 WHERE tenant_id=$1 AND id::text=$2 AND id::text=$3`, tenantID, selector.ID, selector.ParentID, placeholder); err != nil {
				return err
			}
		case "service_account_rotations":
			err := tx.QueryRow(ctx, `SELECT actor FROM service_account_rotations WHERE tenant_id=$1 AND id::text=$2 AND command_id::text=$3 FOR UPDATE`, tenantID, selector.ID, selector.ParentID).Scan(&actor)
			if err == pgx.ErrNoRows {
				continue
			}
			if err != nil {
				return err
			}
			if !subjectValueMatches(tenantID, subjectRef, actor) {
				continue
			}
			if _, err = tx.Exec(ctx, `UPDATE service_account_rotations SET actor=$4 WHERE tenant_id=$1 AND id::text=$2 AND command_id::text=$3`, tenantID, selector.ID, selector.ParentID, placeholder); err != nil {
				return err
			}
		case "service_account_hosts":
			err := tx.QueryRow(ctx, `SELECT saved_by FROM service_account_hosts WHERE tenant_id=$1 AND agent_id::text=$2 AND account_id::text=$3 FOR UPDATE`, tenantID, selector.ID, selector.ParentID).Scan(&actor)
			if err == pgx.ErrNoRows {
				continue
			}
			if err != nil {
				return err
			}
			if !subjectValueMatches(tenantID, subjectRef, actor) {
				continue
			}
			if _, err = tx.Exec(ctx, `UPDATE service_account_hosts SET saved_by=$4 WHERE tenant_id=$1 AND agent_id::text=$2 AND account_id::text=$3`, tenantID, selector.ID, selector.ParentID, placeholder); err != nil {
				return err
			}
		case "service_account_host_scans":
			err := tx.QueryRow(ctx, `SELECT queued_by FROM service_account_host_scans WHERE tenant_id=$1 AND id::text=$2 AND account_id::text=$3 FOR UPDATE`, tenantID, selector.ID, selector.ParentID).Scan(&actor)
			if err == pgx.ErrNoRows {
				continue
			}
			if err != nil {
				return err
			}
			if !subjectValueMatches(tenantID, subjectRef, actor) {
				continue
			}
			if _, err = tx.Exec(ctx, `UPDATE service_account_host_scans SET queued_by=$4 WHERE tenant_id=$1 AND id::text=$2 AND account_id::text=$3`, tenantID, selector.ID, selector.ParentID, placeholder); err != nil {
				return err
			}
		}
	}
	return nil
}

func retainServiceDependentActorsTx(ctx context.Context, tx pgx.Tx, tenantID string, before time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE service_account_rotation_manifests r SET actor='retained:'||left(md5($1::text||':'||actor),12) WHERE r.tenant_id=$1 AND r.created_at<$2 AND r.expires_at<now() AND r.actor NOT LIKE 'retained:%' AND r.actor NOT LIKE 'erased:%' AND NOT EXISTS(SELECT 1 FROM secret_static_rotation_commands c WHERE c.tenant_id=$1 AND c.id=r.id AND c.terminal_at IS NULL)`, tenantID, before); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `UPDATE service_account_hosts SET saved_by='retained:'||left(md5($1::text||':'||saved_by),12) WHERE tenant_id=$1 AND updated_at<$2 AND saved_by NOT LIKE 'retained:%' AND saved_by NOT LIKE 'erased:%'`, tenantID, before); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE service_account_rotations r SET actor='retained:'||left(md5($1::text||':'||actor),12) WHERE r.tenant_id=$1 AND r.created_at<$2 AND r.actor NOT LIKE 'retained:%' AND r.actor NOT LIKE 'erased:%' AND EXISTS(SELECT 1 FROM secret_static_rotation_commands c WHERE c.tenant_id=$1 AND c.id=r.command_id AND c.terminal_at IS NOT NULL)`, tenantID, before); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE service_account_host_scans SET queued_by='retained:'||left(md5($1::text||':'||queued_by),12) WHERE tenant_id=$1 AND queued_at<$2 AND status IN ('complete','partial','failed','superseded') AND queued_by NOT LIKE 'retained:%' AND queued_by NOT LIKE 'erased:%'`, tenantID, before)
	return err
}
