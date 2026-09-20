// SPDX-License-Identifier: BUSL-1.1

package tenantseal

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

const defaultIdempotencyMigrationBatch = 100

// IdempotencyResultMigrationStore is the RLS-scoped persistence seam used by
// ResultMigrator. The concrete production implementation is *store.Store.
type IdempotencyResultMigrationStore interface {
	ListTenants(context.Context) ([]store.Tenant, error)
	ListUnprotectedIdempotencyResults(context.Context, string, string, int) ([]store.UnprotectedIdempotencyResult, error)
	ReplaceUnprotectedIdempotencyResult(context.Context, string, store.UnprotectedIdempotencyResult, []byte) (bool, error)
	IdempotencyResultProtectionStatus(context.Context, string) (store.IdempotencyResultProtectionStatus, error)
	EnforceSealedIdempotencyResultFloor(context.Context) error
}

// ResultMigrator drains rolling-upgrade result codecs into sealed-row-v1. It
// never serializes result bytes into progress, errors, events, or logs.
type ResultMigrator struct {
	store     IdempotencyResultMigrationStore
	protector *ResultProtector
	batchSize int
	sealOnly  bool
}

// NewResultMigrator constructs a resumable tenant-by-tenant migrator.
func NewResultMigrator(
	st IdempotencyResultMigrationStore,
	protector *ResultProtector,
	batchSize int,
	sealOnly bool,
) (*ResultMigrator, error) {
	if st == nil || protector == nil {
		return nil, errors.New("tenantseal: result migration requires store and protector")
	}
	if batchSize == 0 {
		batchSize = defaultIdempotencyMigrationBatch
	}
	if batchSize < 1 || batchSize > 1000 {
		return nil, errors.New("tenantseal: result migration batch must be between 1 and 1000")
	}
	return &ResultMigrator{
		store: st, protector: protector, batchSize: batchSize, sealOnly: sealOnly,
	}, nil
}

// MigrateAll enumerates the system tenant registry, then enters RLS separately
// for each tenant. A failure names only the tenant and row key, never result
// bytes, and leaves already-completed compare-and-swaps resumable.
func (m *ResultMigrator) MigrateAll(ctx context.Context) ([]store.IdempotencyResultProtectionStatus, error) {
	tenants, err := m.store.ListTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenantseal: list tenants for idempotency migration: %w", err)
	}
	statuses := make([]store.IdempotencyResultProtectionStatus, 0, len(tenants))
	for _, tenant := range tenants {
		status, err := m.MigrateTenant(ctx, tenant.TenantID)
		if err != nil {
			return nil, fmt.Errorf("tenantseal: migrate idempotency results for tenant %s: %w", tenant.TenantID, err)
		}
		statuses = append(statuses, status)
	}
	if m.sealOnly {
		if err := m.store.EnforceSealedIdempotencyResultFloor(ctx); err != nil {
			return nil, fmt.Errorf("tenantseal: enforce sealed-only idempotency result floor: %w", err)
		}
	}
	return statuses, nil
}

// MigrateTenant protects every historical raw/dynamic-lease row for one tenant.
func (m *ResultMigrator) MigrateTenant(
	ctx context.Context,
	tenantID string,
) (store.IdempotencyResultProtectionStatus, error) {
	if tenantID == "" {
		return store.IdempotencyResultProtectionStatus{}, errors.New("tenantseal: result migration requires tenant id (AN-1)")
	}
	cursor := ""
	for {
		rows, err := m.store.ListUnprotectedIdempotencyResults(
			ctx, tenantID, cursor, m.batchSize,
		)
		if err != nil {
			return store.IdempotencyResultProtectionStatus{}, err
		}
		if len(rows) == 0 {
			break
		}
		for index := range rows {
			row := &rows[index]
			protectedCodec, protected, err := m.protector.Protect(
				ctx, tenantID, row.Key, row.Binding, row.Result,
			)
			if err != nil {
				secret.Wipe(row.Result)
				return store.IdempotencyResultProtectionStatus{}, fmt.Errorf("protect key %s: %w", row.Key, err)
			}
			if protectedCodec != resultCodecSealedRowV1 {
				secret.Wipe(row.Result)
				secret.Wipe(protected)
				return store.IdempotencyResultProtectionStatus{}, errors.New("tenantseal: result migrator received a non-writable codec")
			}
			replaced, replaceErr := m.store.ReplaceUnprotectedIdempotencyResult(
				ctx, tenantID, *row, protected,
			)
			secret.Wipe(row.Result)
			secret.Wipe(protected)
			if replaceErr != nil {
				return store.IdempotencyResultProtectionStatus{}, fmt.Errorf("replace key %s: %w", row.Key, replaceErr)
			}
			if !replaced {
				return store.IdempotencyResultProtectionStatus{}, fmt.Errorf("key %s changed during migration", row.Key)
			}
			cursor = row.Key
		}
	}
	status, err := m.store.IdempotencyResultProtectionStatus(ctx, tenantID)
	if err != nil {
		return store.IdempotencyResultProtectionStatus{}, err
	}
	if status.RemainingLegacy() != 0 {
		return status, fmt.Errorf("tenantseal: tenant %s still has %d legacy idempotency results", tenantID, status.RemainingLegacy())
	}
	return status, nil
}
