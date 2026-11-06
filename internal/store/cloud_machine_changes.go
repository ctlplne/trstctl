// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
)

const cloudChangeColumns = `id::text,tenant_id::text,intent,state,approval_request_id::text,intent_digest,requested_by,created_at,updated_at,expires_at,result,event_sequence`

func scanCloudChange(row interface{ Scan(...any) error }) (change.Record, error) {
	var out change.Record
	var intent, result []byte
	err := row.Scan(&out.ID, &out.TenantID, &intent, &out.State, &out.ApprovalRequestID, &out.IntentDigest, &out.RequestedBy, &out.CreatedAt, &out.UpdatedAt, &out.ExpiresAt, &result, &out.EventSequence)
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(intent, &out.Intent); err != nil {
		return out, err
	}
	if len(result) > 0 && string(result) != "null" {
		var value change.Result
		if err = json.Unmarshal(result, &value); err != nil {
			return out, err
		}
		out.Result = &value
	}
	return out, nil
}
func (s *Store) GetCloudMachineChange(ctx context.Context, tenantID, id string) (change.Record, error) {
	var out change.Record
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanCloudChange(tx.QueryRow(ctx, `SELECT `+cloudChangeColumns+` FROM cloud_machine_changes WHERE tenant_id=$1 AND id=$2`, tenantID, id))
		return err
	})
	return out, err
}
func (s *Store) GetCloudMachineChangeTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (change.Record, error) {
	return scanCloudChange(tx.QueryRow(ctx, `SELECT `+cloudChangeColumns+` FROM cloud_machine_changes WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, id))
}

func (s *Store) ListCloudMachineChanges(ctx context.Context, tenantID, after string, limit int) ([]change.Record, error) {
	return s.ListCloudMachineChangesForFinding(ctx, tenantID, "", after, limit)
}

func (s *Store) ListCloudMachineChangesForFinding(ctx context.Context, tenantID, findingID, after string, limit int) ([]change.Record, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	if after == "" {
		after = ZeroUUID
	}
	var out []change.Record
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+cloudChangeColumns+` FROM cloud_machine_changes WHERE tenant_id=$1 AND id>$2 AND ($4='' OR intent->>'finding_id'=$4) ORDER BY id LIMIT $3`, tenantID, after, limit, findingID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanCloudChange(rows)
			if err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

// ApplyCloudMachineChangeProposedTx projects immutable public intent only.
func (s *Store) ApplyCloudMachineChangeProposedTx(ctx context.Context, tx pgx.Tx, tenantID string, value change.Record, sequence uint64) error {
	intent, err := json.Marshal(value.Intent)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO cloud_machine_changes (tenant_id,id,intent,state,approval_request_id,intent_digest,requested_by,created_at,updated_at,expires_at,event_sequence) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8,$9,$10) ON CONFLICT (tenant_id,id) DO NOTHING`, tenantID, value.ID, intent, change.AwaitingApproval, value.ApprovalRequestID, value.IntentDigest, value.RequestedBy, value.CreatedAt, value.ExpiresAt, sequence)
	return err
}
func (s *Store) ApplyCloudMachineChangeProgressedTx(ctx context.Context, tx pgx.Tx, tenantID, id, state string, result *change.Result, sequence uint64, at time.Time) error {
	if !change.ValidState(state) || state == change.AwaitingApproval {
		return errors.New("invalid cloud change progress state")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE cloud_machine_changes SET state=$3,result=$4,event_sequence=$5,updated_at=$6 WHERE tenant_id=$1 AND id=$2 AND event_sequence<$5 AND (state='queued' OR (state='awaiting_approval' AND $3='queued'))`, tenantID, id, state, raw, sequence, at)
	return err
}
