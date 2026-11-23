// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

// TenantKeyRecoveryDomainStore reads the event-derived key snapshot for one
// exact rebuild/restore operation. It never falls back to the read model being
// replaced by that operation.
type TenantKeyRecoveryDomainStore struct {
	store       *Store
	operationID string
}

func (s *Store) NewTenantKeyRecoveryDomainStore(operationID string) (*TenantKeyRecoveryDomainStore, error) {
	if s == nil {
		return nil, errors.New("store: recovery domain store requires PostgreSQL")
	}
	if _, err := uuid.Parse(operationID); err != nil {
		return nil, errors.New("store: recovery domain store requires an operation UUID")
	}
	return &TenantKeyRecoveryDomainStore{store: s, operationID: operationID}, nil
}

// StageTenantKeyRecoverySnapshot stores one validated event-derived snapshot
// under its tenant and recovery operation. An exact retry is idempotent; the
// same event ID with different bytes or sequence is a conflict.
func (s *Store) StageTenantKeyRecoverySnapshot(ctx context.Context, operationID string, domain TenantKeyDomain) error {
	if _, err := uuid.Parse(operationID); err != nil || domain.TenantID == "" ||
		domain.DomainID == "" || domain.LastTransitionEventID == "" || domain.LastTransitionSequence == 0 ||
		domain.LastTransitionSequence > math.MaxInt64 {
		return errors.New("store: recovery key snapshot is incomplete")
	}
	raw, err := json.Marshal(domain)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return errors.New("store: recovery key snapshot exceeds the bounded record size")
	}
	digest := crypto.SHA256Hex(raw)
	return s.WithTenantProjection(ctx, domain.TenantID, func(tx pgx.Tx) error {
		var lifecycle string
		err := tx.QueryRow(ctx, `SELECT record_kind FROM trstctl_recovery.tenant_key_domain_snapshots
			WHERE tenant_id=$1 AND operation_id=$2 AND source_sequence < $3
			  AND record_kind <> 'key_domain'
			ORDER BY source_sequence DESC LIMIT 1`, domain.TenantID, operationID,
			// #nosec G115 -- LastTransitionSequence was bounded to MaxInt64 before the transaction
			int64(domain.LastTransitionSequence)).Scan(&lifecycle)
		if err != nil {
			return err
		}
		if lifecycle != "tenant_registered" {
			return errors.New("store: recovery key snapshot belongs to an offboarded lifecycle")
		}
		tag, err := tx.Exec(ctx, `INSERT INTO trstctl_recovery.tenant_key_domain_snapshots
			(tenant_id,operation_id,event_id,source_sequence,snapshot_sha256,snapshot)
			VALUES ($1,$2,$3,$4,$5,$6::jsonb)
			ON CONFLICT (tenant_id,operation_id,event_id) DO UPDATE
			SET source_sequence=EXCLUDED.source_sequence
			WHERE trstctl_recovery.tenant_key_domain_snapshots.source_sequence=EXCLUDED.source_sequence
			  AND trstctl_recovery.tenant_key_domain_snapshots.snapshot_sha256=EXCLUDED.snapshot_sha256`,
			domain.TenantID, operationID, domain.LastTransitionEventID,
			// #nosec G115 -- LastTransitionSequence was bounded to MaxInt64 before the transaction
			int64(domain.LastTransitionSequence), digest, raw)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("store: recovery key snapshot changed for an event")
		}
		return nil
	})
}

// StageTenantKeyRecoveryLifecycle records the registration boundary before a
// key-domain snapshot may be used. The latest registration/offboard event, not
// an old UUID alone, decides whether a recovered key belongs to this lifecycle.
func (s *Store) StageTenantKeyRecoveryLifecycle(
	ctx context.Context, operationID, tenantID, eventID string, sequence uint64, registered bool,
) error {
	if _, err := uuid.Parse(operationID); err != nil || tenantID == "" || eventID == "" ||
		sequence == 0 || sequence > math.MaxInt64 {
		return errors.New("store: recovery tenant lifecycle marker is incomplete")
	}
	kind := "tenant_offboarded"
	if registered {
		kind = "tenant_registered"
	}
	digest := crypto.SHA256Hex([]byte("{}"))
	return s.WithTenantProjection(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO trstctl_recovery.tenant_key_domain_snapshots
			(tenant_id,operation_id,event_id,record_kind,source_sequence,snapshot_sha256,snapshot)
			VALUES ($1,$2,$3,$4,$5,$6,'{}'::jsonb)
			ON CONFLICT (tenant_id,operation_id,event_id) DO UPDATE
			SET source_sequence=EXCLUDED.source_sequence
			WHERE trstctl_recovery.tenant_key_domain_snapshots.source_sequence=EXCLUDED.source_sequence
			  AND trstctl_recovery.tenant_key_domain_snapshots.record_kind=EXCLUDED.record_kind
			  AND trstctl_recovery.tenant_key_domain_snapshots.snapshot_sha256=EXCLUDED.snapshot_sha256`,
			tenantID, operationID, eventID, kind,
			// #nosec G115 -- sequence was bounded to MaxInt64 before the transaction
			int64(sequence), digest)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("store: recovery lifecycle marker changed for an event")
		}
		return nil
	})
}

func (r *TenantKeyRecoveryDomainStore) readTx(ctx context.Context, tx pgx.Tx, tenantID string) (*TenantKeyDomain, error) {
	var raw []byte
	var digest, eventID, recordKind string
	var sequence int64
	err := tx.QueryRow(ctx, `SELECT snapshot::text,snapshot_sha256,event_id,source_sequence,record_kind
		FROM trstctl_recovery.tenant_key_domain_snapshots
		WHERE tenant_id=$1 AND operation_id=$2
		ORDER BY source_sequence DESC LIMIT 1`, tenantID, r.operationID).
		Scan(&raw, &digest, &eventID, &sequence, &recordKind)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if recordKind != "key_domain" {
		if recordKind != "tenant_registered" && recordKind != "tenant_offboarded" ||
			string(raw) != "{}" || crypto.SHA256Hex(raw) != digest {
			return nil, errors.New("store: recovery lifecycle marker binding changed")
		}
		return nil, nil
	}
	var domain TenantKeyDomain
	if err := json.Unmarshal(raw, &domain); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(domain)
	if err != nil {
		return nil, err
	}
	if crypto.SHA256Hex(canonical) != digest || domain.TenantID != tenantID ||
		domain.LastTransitionEventID != eventID || sequence <= 0 ||
		domain.LastTransitionSequence != uint64(sequence) {
		return nil, errors.New("store: recovery key snapshot binding changed")
	}
	return &domain, nil
}

func (r *TenantKeyRecoveryDomainStore) WithTenantKeyDomainShared(ctx context.Context, tenantID string, fn func(*TenantKeyDomain) error) error {
	if r == nil || r.store == nil || tenantID == "" || fn == nil {
		return errors.New("store: recovery tenant key access is incomplete")
	}
	return r.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := r.store.LockTenantKeyDomainSharedTx(ctx, tx, tenantID); err != nil {
			return err
		}
		domain, err := r.readTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		return fn(domain)
	})
}

func (r *TenantKeyRecoveryDomainStore) WithTenantKeyDomainSharedDeployment(
	ctx context.Context, tenantID string,
	fn func(*TenantKeyDomain, *DeploymentKEKDomain) error,
) error {
	if r == nil || r.store == nil || tenantID == "" || fn == nil {
		return errors.New("store: recovery tenant/deployment key access is incomplete")
	}
	return r.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := r.store.LockTenantKeyDomainSharedTx(ctx, tx, tenantID); err != nil {
			return err
		}
		var deployment *DeploymentKEKDomain
		if state, found, err := r.store.DeploymentKEKDomainTx(ctx, tx); err != nil {
			return fmt.Errorf("store: read deployment key state for recovery: %w", err)
		} else if found {
			deployment = &state
		}
		domain, err := r.readTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		return fn(domain, deployment)
	})
}

// ClearTenantKeyRecoverySnapshots removes only this tenant's completed
// operation rows. A crashed operation keeps its rows for fenced diagnosis.
func (s *Store) ClearTenantKeyRecoverySnapshots(ctx context.Context, tenantID, operationID string) error {
	if tenantID == "" {
		return errors.New("store: recovery snapshot cleanup requires tenant")
	}
	if _, err := uuid.Parse(operationID); err != nil {
		return errors.New("store: recovery snapshot cleanup requires operation UUID")
	}
	return s.WithTenantProjection(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM trstctl_recovery.tenant_key_domain_snapshots
			WHERE tenant_id=$1 AND operation_id=$2`, tenantID, operationID)
		return err
	})
}

// ClearTenantKeyRecoverySnapshotsTx consumes one successful rebuild's staging
// rows inside the same atomic read-model transaction. A rollback leaves the
// operation evidence available for diagnosis and exact retry.
func (s *Store) ClearTenantKeyRecoverySnapshotsTx(ctx context.Context, tx pgx.Tx, operationID string) error {
	if _, err := uuid.Parse(operationID); err != nil || tx == nil {
		return errors.New("store: recovery snapshot transaction cleanup is incomplete")
	}
	//trstctl:system-query — cross-tenant system atomic rebuild enumerates tenant_id only for this exact recovery operation; each cleanup delete uses both tenant_id and operation_id predicates.
	rows, err := tx.Query(ctx, `SELECT DISTINCT tenant_id::text
		FROM trstctl_recovery.tenant_key_domain_snapshots
		WHERE operation_id=$1 ORDER BY tenant_id`, operationID)
	if err != nil {
		return err
	}
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			rows.Close()
			return err
		}
		tenants = append(tenants, tenantID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, tenantID := range tenants {
		if _, err := tx.Exec(ctx, `DELETE FROM trstctl_recovery.tenant_key_domain_snapshots
			WHERE tenant_id=$1 AND operation_id=$2`, tenantID, operationID); err != nil {
			return err
		}
	}
	return nil
}
