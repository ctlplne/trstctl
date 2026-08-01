// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package orchestrator runs idempotent PCAS succession jobs. A job mints a
// successor through the signer, then appends the succession record and a
// transactional-outbox publish intent in the SAME database transaction (PCAS-claim-6 /
// INV-4), so publication is exactly-once under retries. It reuses the MPL core
// store, its RLS-scoped transaction, and the core outbox table; it forks none of
// them (AN-6).
package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

// PublishDestination is the outbox destination for relying-party publication of a
// minted succession record.
const PublishDestination = "pcas.rp-publish"

// Minter mints a successor inside the signer (signing.SuccessionMinter).
type Minter interface {
	MintSuccessor(ctx context.Context, req signing.MintRequest) (signing.MintResult, error)
}

// Result is the outcome of a succession job.
type Result struct {
	Epoch    uint64
	Record   []byte // encoded dual-signed succession record
	Replayed bool   // true when returned from a prior run under the same idempotency key
}

// Orchestrator runs succession jobs against the core store + signer minter.
type Orchestrator struct {
	core   *corestore.Store
	minter Minter
}

// New returns an Orchestrator.
func New(core *corestore.Store, m Minter) *Orchestrator { return &Orchestrator{core: core, minter: m} }

// RunSuccession mints and records a succession for tenantID under idempotencyKey.
// A retry with the same key returns the original record without minting again
// (exactly-once effect, PCAS-claim-6 / INV-4). On a new key it mints, then appends the
// record and the outbox publish intent in one transaction.
func (o *Orchestrator) RunSuccession(ctx context.Context, tenantID string, req signing.MintRequest, idempotencyKey string) (Result, error) {
	if idempotencyKey == "" {
		return Result{}, errors.New("orchestrator: idempotency key required (AN-5)")
	}

	// Replay: return the already-recorded record for this key without minting.
	if rec, epoch, ok, err := o.fetchByKey(ctx, tenantID, idempotencyKey); err != nil {
		return Result{}, err
	} else if ok {
		return Result{Epoch: epoch, Record: rec, Replayed: true}, nil
	}

	// New key: mint through the signer.
	res, err := o.minter.MintSuccessor(ctx, req)
	if err != nil {
		return Result{}, fmt.Errorf("orchestrator: mint: %w", err)
	}
	decoded, err := minter.DecodeRecord(res.EncodedRecord)
	if err != nil {
		return Result{}, fmt.Errorf("orchestrator: decode minted record: %w", err)
	}

	// Same transaction: append the succession record AND the outbox publish intent
	// (PCAS-claim-6 / INV-4). At-least-once delivery by a separate worker, rendered
	// exactly-once by idempotency, is the AN-6 discipline.
	err = o.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO succession_records
			   (tenant_id, identity_id, epoch, predecessor_epoch, predecessor_alg, successor_alg, successor_pub, record, idempotency_key)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8)`,
			decoded.Fields.IdentityID, decoded.Fields.Epoch, decoded.Fields.PredecessorEpoch,
			string(decoded.Fields.PredecessorAlg), string(decoded.Fields.SuccessorAlg),
			decoded.Fields.SuccessorPub, res.EncodedRecord, idempotencyKey); err != nil {
			return fmt.Errorf("append record: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3)`,
			PublishDestination, res.EncodedRecord, idempotencyKey); err != nil {
			return fmt.Errorf("enqueue outbox: %w", err)
		}
		// Advance the serving high-water in the SAME transaction, monotonically, so the
		// next succession for this identity resolves its predecessor at the new epoch
		// (INT-03) and a crash can never leave the record and the high-water disagreeing.
		if _, err := tx.Exec(ctx,
			`INSERT INTO identity_algorithm_epoch (tenant_id, identity_id, epoch)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2)
			 ON CONFLICT (tenant_id, identity_id)
			 DO UPDATE SET epoch = EXCLUDED.epoch
			 WHERE identity_algorithm_epoch.epoch < EXCLUDED.epoch`,
			decoded.Fields.IdentityID, decoded.Fields.Epoch); err != nil {
			return fmt.Errorf("advance high-water: %w", err)
		}
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("orchestrator: record+outbox transaction: %w", err)
	}
	return Result{Epoch: res.Epoch, Record: res.EncodedRecord}, nil
}

func (o *Orchestrator) fetchByKey(ctx context.Context, tenantID, key string) (record []byte, epoch uint64, ok bool, err error) {
	err = o.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT record, epoch FROM succession_records
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND idempotency_key = $1`, key).
			Scan(&record, &epoch)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		ok = true
		return nil
	})
	return record, epoch, ok, err
}
