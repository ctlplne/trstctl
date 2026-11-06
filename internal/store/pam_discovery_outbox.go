// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/pamdiscovery"
)

func (s *Store) ApplyPAMDiscoveryScanQueuedTx(ctx context.Context, tx pgx.Tx, tenantID string, intent pamdiscovery.ScanIntent) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if err := lockPAMDiscoverySourceTx(ctx, tx, tenantID, intent.ProviderID); err != nil {
		return err
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO pam_discovery_runs(tenant_id,id,provider_id,status,started_at,finished_at,requested_by,scan_intent)
 VALUES($1,$2,$3,'queued',$4,NULL,$5,$6::jsonb) ON CONFLICT(tenant_id,id) DO NOTHING`, tenantID, intent.RunID, intent.ProviderID, intent.QueuedAt, intent.RequestedBy, raw)
	if err != nil {
		return err
	}
	var state string
	var existing []byte
	if err = tx.QueryRow(ctx, `SELECT status,scan_intent FROM pam_discovery_runs WHERE tenant_id=$1 AND id=$2`, tenantID, intent.RunID).Scan(&state, &existing); err != nil {
		return err
	}
	var canonical pamdiscovery.ScanIntent
	if json.Unmarshal(existing, &canonical) != nil || canonical != intent {
		return ErrIdempotencyConflict
	}
	if state != "queued" {
		return nil
	}
	id, err := ensureSecretIntegrationOutboxTx(ctx, tx, tenantID, pamdiscovery.ScanDestination, "pam-discovery-source:"+intent.ProviderID, "pam-discovery:"+intent.RunID, raw)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE pam_discovery_runs SET outbox_id=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, intent.RunID, id)
	return err
}
func (s *Store) PendingPAMDiscoveryScan(ctx context.Context, tenantID, providerID string) (bool, error) {
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pam_discovery_runs WHERE tenant_id=$1 AND provider_id=$2 AND status='queued')`, tenantID, providerID).Scan(&pending)
	})
	return pending, err
}
func (s *Store) GetPAMDiscoveryScanIntent(ctx context.Context, tenantID, runID string) (pamdiscovery.ScanIntent, *int64, error) {
	var value pamdiscovery.ScanIntent
	var jobID *int64
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT scan_intent,outbox_id FROM pam_discovery_runs WHERE tenant_id=$1 AND id=$2`, tenantID, runID).Scan(&raw, &jobID); err != nil {
			return err
		}
		if len(raw) == 0 || len(raw) > 8192 {
			return errors.New("store: discovery source intent unavailable")
		}
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		return value.Validate()
	})
	return value, jobID, err
}

// Both the queued insert and completion upsert share the secondary source key.
func lockPAMDiscoverySourceTx(ctx context.Context, tx pgx.Tx, tenantID, providerID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "pam-discovery-source\x1f"+tenantID+"\x1f"+providerID)
	return err
}
