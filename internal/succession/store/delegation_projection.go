// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/delegation"
)

// DelegationProjection restores the PCAS signer-confirmed serving table from
// its immutable signed receipts. It joins core's full rebuild transaction.
type DelegationProjection struct{ store *corestore.Store }

func NewDelegationProjection(store *corestore.Store) *DelegationProjection {
	return &DelegationProjection{store: store}
}

func (*DelegationProjection) Name() string             { return "pcas.delegation" }
func (*DelegationProjection) ProjectsTenantLifecycle() {}

func (p *DelegationProjection) Reset(ctx context.Context) error {
	return p.withSystemTx(ctx, func(tx pgx.Tx) error { return p.ResetTx(ctx, tx) })
}

func (p *DelegationProjection) Apply(ctx context.Context, ev eventspec.Event) error {
	if ev.Type != succession.TypeDelegationApplied && ev.Type != projections.EventTenantOffboarded {
		return nil
	}
	return p.withSystemTx(ctx, func(tx pgx.Tx) error { return p.ApplyTx(ctx, tx, ev) })
}

func (p *DelegationProjection) withSystemTx(ctx context.Context, apply func(pgx.Tx) error) error {
	if p == nil || p.store == nil {
		return errors.New("pcas delegation: projection store unavailable")
	}
	tx, err := p.store.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := apply(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *DelegationProjection) ResetTx(ctx context.Context, tx pgx.Tx) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("pcas delegation: projection store unavailable")
	}
	//trstctl:system-query — a full replay resets this derived table for every tenant before replaying exact tenant-bound events.
	_, err := tx.Exec(ctx, `DELETE FROM pcas_delegation_scope`)
	return err
}

func (p *DelegationProjection) ApplyTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("pcas delegation: projection store unavailable")
	}
	if ev.Type == projections.EventTenantOffboarded {
		_, err := tx.Exec(ctx, `DELETE FROM pcas_delegation_scope WHERE tenant_id = $1`, ev.TenantID)
		return err
	}
	if ev.Type != succession.TypeDelegationApplied {
		return nil
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	payload, ok := decoded.(succession.DelegationAppliedV1)
	if !ok {
		return nil // future version is deliberately skipped
	}
	if payload.TenantID != ev.TenantID {
		return errors.New("pcas delegation: event payload tenant mismatch")
	}
	var receipt delegation.Receipt
	if err := json.Unmarshal(payload.ReceiptJSON, &receipt); err != nil {
		return fmt.Errorf("pcas delegation: decode signed receipt: %w", err)
	}
	return ApplyDelegationReceiptTx(ctx, tx, ev.TenantID, ev.Sequence, receipt)
}

func (p *DelegationProjection) ReplayTenantLifecycleTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	return p.ApplyTx(ctx, tx, ev)
}
