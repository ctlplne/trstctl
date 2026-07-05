// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package store is the tenant-scoped (RLS) persistence for PCAS: the durable
// succession-record chain and the serving copy of each identity's algorithm-epoch
// high-water. It layers on the MPL core store through the feature-neutral
// WithExtraMigrations seam and the RLS-scoped Store.WithTenant transaction; it
// forks neither the core store nor its migration runner (AN-1, AN-9).
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"

	corestore "trstctl.com/trstctl/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrationsFS returns the PCAS succession DDL as a migration source for the core
// store's feature-neutral WithExtraMigrations seam. It is wired only through the
// tagged ee_attach seam (PCAS-08); the core-only build never references it, so the
// core-only build applies zero PCAS migrations (G6).
func MigrationsFS() fs.FS { return migrationsFS }

// ErrHighWaterRegression is returned by UpsertHighWater when the requested epoch
// is not strictly greater than the stored high-water (defense in depth; the
// signer floor is the authority, INV-3).
var ErrHighWaterRegression = errors.New("succession store: high-water cannot regress")

// Record is a durable succession-chain row (one per succession record). It holds
// public key material and the opaque encoded record only; no private keys (AN-8).
type Record struct {
	IdentityID       string
	Epoch            uint64
	PredecessorEpoch uint64
	PredecessorAlg   string
	SuccessorAlg     string
	SuccessorPub     []byte
	Encoded          []byte // opaque encoded dual-signed record (PCAS-04)
}

// Repo is the tenant-scoped repository. Every method runs inside the core store's
// RLS-scoped transaction (Store.WithTenant), so row-level security confines all
// access to the caller's tenant (AN-1, claim 7 / INV-5 RLS half).
type Repo struct {
	core *corestore.Store
}

// New returns a Repo over the core store.
func New(core *corestore.Store) *Repo { return &Repo{core: core} }

// AppendRecord inserts a succession record for tenantID. The tenant_id column is
// bound from the RLS session setting, so the row is always the caller's tenant
// (the RLS WITH CHECK enforces it).
func (r *Repo) AppendRecord(ctx context.Context, tenantID string, rec Record) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO succession_records
			   (tenant_id, identity_id, epoch, predecessor_epoch, predecessor_alg, successor_alg, successor_pub, record)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7)`,
			rec.IdentityID, rec.Epoch, rec.PredecessorEpoch, rec.PredecessorAlg, rec.SuccessorAlg, rec.SuccessorPub, rec.Encoded)
		if err != nil {
			return fmt.Errorf("succession store: append record: %w", err)
		}
		return nil
	})
}

// FetchChain returns identityID's succession records ordered and complete by
// epoch ascending, scoped to tenantID by RLS.
func (r *Repo) FetchChain(ctx context.Context, tenantID, identityID string) ([]Record, error) {
	var out []Record
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT identity_id, epoch, predecessor_epoch, predecessor_alg, successor_alg, successor_pub, record
			   FROM succession_records
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1
			  ORDER BY epoch ASC`, identityID)
		if err != nil {
			return fmt.Errorf("succession store: fetch chain: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var rec Record
			if err := rows.Scan(&rec.IdentityID, &rec.Epoch, &rec.PredecessorEpoch, &rec.PredecessorAlg, &rec.SuccessorAlg, &rec.SuccessorPub, &rec.Encoded); err != nil {
				return fmt.Errorf("succession store: scan record: %w", err)
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertHighWater advances the serving high-water for identityID to epoch. It is
// monotonic: an equal or lower epoch is rejected (ErrHighWaterRegression) and
// leaves the stored value unchanged.
func (r *Repo) UpsertHighWater(ctx context.Context, tenantID, identityID string, epoch uint64) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`INSERT INTO identity_algorithm_epoch (tenant_id, identity_id, epoch)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2)
			 ON CONFLICT (tenant_id, identity_id)
			 DO UPDATE SET epoch = EXCLUDED.epoch, updated_at = now()
			 WHERE identity_algorithm_epoch.epoch < EXCLUDED.epoch`,
			identityID, epoch)
		if err != nil {
			return fmt.Errorf("succession store: upsert high-water: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return fmt.Errorf("%w: identity %q epoch %d", ErrHighWaterRegression, identityID, epoch)
		}
		return nil
	})
}

// GetHighWater returns the serving high-water epoch for identityID and whether a
// row exists, scoped to tenantID by RLS.
func (r *Repo) GetHighWater(ctx context.Context, tenantID, identityID string) (epoch uint64, found bool, err error) {
	err = r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT epoch FROM identity_algorithm_epoch
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1`, identityID).Scan(&epoch)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return fmt.Errorf("succession store: get high-water: %w", e)
		}
		found = true
		return nil
	})
	return epoch, found, err
}
