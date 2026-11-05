// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// PAMGatewayAWSScope reads the session's original outbox intent, rather than a
// provider's possibly changed configuration. No credential is in this payload.
func (s *Store) PAMGatewayAWSScope(ctx context.Context, tenantID, sessionID string) (service, region string, err error) {
	err = s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT payload FROM outbox WHERE tenant_id=$1 AND destination='access.gateway.session' AND idempotency_key=$2 ORDER BY id LIMIT 2`, tenantID, "pam-gateway:"+sessionID)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return pgx.ErrNoRows
		}
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		if rows.Next() {
			return errors.New("store: duplicate gateway session intent")
		}
		if err := rows.Err(); err != nil {
			return err
		}
		var intent struct {
			SessionID  string `json:"session_id"`
			TargetType string `json:"target_type"`
			AWSService string `json:"aws_service"`
			AWSRegion  string `json:"aws_region"`
		}
		if json.Unmarshal(raw, &intent) != nil || intent.SessionID != sessionID || intent.TargetType != "aws" || (intent.AWSService != "s3" && intent.AWSService != "sts") || intent.AWSRegion == "" {
			return errors.New("store: invalid frozen AWS gateway scope")
		}
		service, region = intent.AWSService, intent.AWSRegion
		return nil
	})
	return
}
