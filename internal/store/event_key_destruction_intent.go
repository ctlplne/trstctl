// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprotect"
)

const EventKeyDestructionDestination = "eventprivacy.destroy"

func EventKeyDestructionOutboxKey(operationID string) string {
	return EventKeyDestructionDestination + ":" + operationID
}

// OffboardTenantForEventKeyDestructionTx keeps the normal erase's strict
// verification, then adds one public pending effect in the SAME transaction.
// The caller must derive request from retained source. This method grants no key
// I/O: the receiver separately verifies its committed claim, source and holds.
// A replay inspects its exact sole residue; it never deletes a pending receiver.
func (s *Store) OffboardTenantForEventKeyDestructionTx(ctx context.Context, tx pgx.Tx, request eventprotect.DestructionRequest) (TenantDeletionAttestation, error) {
	tenantID := request.Ref.TenantID
	att := newTenantDeletionAttestation(tenantID)
	if s == nil || tx == nil || request.Validate() != nil {
		return att, errors.New("store: invalid event key destruction intent")
	}
	request.OffboardedAt, request.NotBefore = request.OffboardedAt.UTC(), request.NotBefore.UTC()
	payload, err := json.Marshal(request)
	if err != nil {
		return att, err
	}
	var scope string
	if err := tx.QueryRow(ctx, `SELECT current_setting('trstctl.tenant_id',true)`).Scan(&scope); err != nil {
		return att, err
	}
	if scope != tenantID {
		return att, errors.New("store: event key destruction transaction belongs to another tenant")
	}
	// Match the existing offboard lock order even when resuming an erased row.
	var privacyShared bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock_shared($1)`, HistoryRewriteOperationAdvisoryLockKey).Scan(&privacyShared); err != nil {
		return att, err
	}
	if !privacyShared {
		return att, ErrPrivacyHistoryOperationActive
	}
	if err := s.TryTenantLifecycleCommitTx(ctx, tx, tenantID); err != nil {
		return att, err
	}
	if _, err := lockTenantRegistrationForOffboardTx(ctx, tx, tenantID); err != nil {
		return att, err
	}
	key := EventKeyDestructionOutboxKey(request.OperationID)
	var existing []byte
	var destination, lane, role, agent string
	err = tx.QueryRow(ctx, `SELECT payload,destination,COALESCE(NULLIF(effect_lane,''),destination),
	 required_agent_role,COALESCE(required_agent_id::text,'') FROM outbox
	 WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE`, tenantID, key).Scan(&existing, &destination, &lane, &role, &agent)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		att, err = s.OffboardTenantTx(ctx, tx, tenantID)
		if err != nil {
			return att, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO outbox
		 (tenant_id,destination,effect_lane,payload,idempotency_key,required_agent_role,next_attempt_at)
		 VALUES ($1,$2,$2,$3,$4,'control_plane',$5)`, tenantID, EventKeyDestructionDestination, payload, key, request.NotBefore); err != nil {
			return att, fmt.Errorf("store: queue independent event key destruction: %w", err)
		}
	case err != nil:
		return att, err
	case destination != EventKeyDestructionDestination || lane != EventKeyDestructionDestination || role != "control_plane" || agent != "" || !bytes.Equal(existing, payload):
		return att, fmt.Errorf("%w: event key destruction intent differs", ErrIdempotencyConflict)
	}
	// This is an honest pending attestation, never the ordinary Complete=true.
	// Any unexpected residue refuses rather than being silently erased on retry.
	att.Complete = false
	for _, table := range TenantScopedTables {
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenantID).Scan(&count); err != nil {
			return att, err
		}
		expected := 0
		if table == "outbox" {
			expected = 1
		}
		if count != expected {
			return att, fmt.Errorf("store: pending event key destruction has unexpected %s residue: %d", table, count)
		}
		if count != 0 {
			att.Residue[table] = count
		}
	}
	// OIDC locators are held in a fixed auth partition. Inspect this customer's
	// exact references as well; a default customer RLS count cannot see them.
	if err := verifyNoOffboardOIDCLocatorsTx(ctx, tx, tenantID); err != nil {
		return att, err
	}
	return att, nil
}

func verifyNoOffboardOIDCLocatorsTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	var priorTenant, priorSearchPath string
	if err := tx.QueryRow(ctx, `SELECT current_setting('trstctl.tenant_id'),current_setting('search_path')`).Scan(&priorTenant, &priorSearchPath); err != nil {
		return err
	}
	if priorTenant != tenantID {
		return errors.New("store: pending event key destruction lost its tenant scope")
	}
	if err := setOIDCAuthScopeTx(ctx, tx); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM oidc_session_locators
	 WHERE tenant_id=$1 AND browser_tenant_id=$2`, oidcAuthPartition, tenantID).Scan(&count); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true),set_config('search_path',$2,true)`, priorTenant, priorSearchPath); err != nil {
		return err
	}
	if count != 0 {
		return errors.New("store: pending event key destruction has unexpected browser locator residue")
	}
	return nil
}
