// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
)

// IssuerAuthorityProjection rebuilds a tenant's public PCAS issuer bindings
// from their immutable source events. Legacy direct-write rows are not served.
type IssuerAuthorityProjection struct{ store *corestore.Store }

func NewIssuerAuthorityProjection(store *corestore.Store) *IssuerAuthorityProjection {
	return &IssuerAuthorityProjection{store: store}
}

func (*IssuerAuthorityProjection) Name() string             { return "pcas.issuer.authority" }
func (*IssuerAuthorityProjection) ProjectsTenantLifecycle() {}

func (p *IssuerAuthorityProjection) Reset(ctx context.Context) error {
	return p.withSystemTx(ctx, func(tx pgx.Tx) error { return p.ResetTx(ctx, tx) })
}

func (p *IssuerAuthorityProjection) Apply(ctx context.Context, ev eventspec.Event) error {
	if ev.Type != succession.TypeIssuerAuthorityRegistered && ev.Type != projections.EventTenantOffboarded {
		return nil
	}
	if p == nil || p.store == nil {
		return errors.New("pcas issuer: projection store unavailable")
	}
	if ev.Type == projections.EventTenantOffboarded {
		return p.withSystemTx(ctx, func(tx pgx.Tx) error { return p.ApplyTx(ctx, tx, ev) })
	}
	return p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error { return p.ApplyTx(ctx, tx, ev) })
}

func (p *IssuerAuthorityProjection) withSystemTx(ctx context.Context, apply func(pgx.Tx) error) error {
	if p == nil || p.store == nil {
		return errors.New("pcas issuer: projection store unavailable")
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

func (p *IssuerAuthorityProjection) ResetTx(ctx context.Context, tx pgx.Tx) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("pcas issuer: projection store unavailable")
	}
	//trstctl:system-query — explicit full replay resets only this derived table; tenant-bound source events rebuild it.
	_, err := tx.Exec(ctx, `DELETE FROM pcas_issuer_authority`)
	return err
}

func (p *IssuerAuthorityProjection) ApplyTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("pcas issuer: projection store unavailable")
	}
	if ev.Type == projections.EventTenantOffboarded {
		_, err := tx.Exec(ctx, `DELETE FROM pcas_issuer_authority WHERE tenant_id = $1`, ev.TenantID)
		return err
	}
	if ev.Type != succession.TypeIssuerAuthorityRegistered {
		return nil
	}
	return ApplyIssuerAuthorityEventTx(ctx, tx, ev)
}

func (p *IssuerAuthorityProjection) ReplayTenantLifecycleTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	return p.ApplyTx(ctx, tx, ev)
}

// ApplyIssuerAuthorityEventTx is sequence-fenced so a delayed predecessor
// cannot replace a newer registered CA or PCAS epoch after a crash.
func ApplyIssuerAuthorityEventTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Type != succession.TypeIssuerAuthorityRegistered || ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return errors.New("pcas issuer: invalid source event")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	payload, ok := decoded.(succession.IssuerAuthorityRegisteredV1)
	if !ok {
		return nil // never interpret a future schema as current authority
	}
	if payload.TenantID != ev.TenantID || payload.CurrentEpoch > math.MaxInt64 ||
		strings.TrimSpace(payload.IssuerID) == "" || strings.TrimSpace(payload.IssuerID) != payload.IssuerID ||
		strings.TrimSpace(payload.IdentityID) == "" || strings.TrimSpace(payload.IdentityID) != payload.IdentityID ||
		strings.TrimSpace(payload.CAKeyHandle) == "" || strings.TrimSpace(payload.CAKeyHandle) != payload.CAKeyHandle {
		return errors.New("pcas issuer: event tenant or authority binding is invalid")
	}
	if _, err := crypto.PublicKeyDERFromCert(payload.CACertDER); err != nil {
		return fmt.Errorf("pcas issuer: source CA certificate is invalid: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO pcas_issuer_authority
		(tenant_id, issuer_id, identity_id, current_epoch, ca_key_handle, ca_cert_der, updated_at, source_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, issuer_id) DO UPDATE SET
		identity_id = EXCLUDED.identity_id, current_epoch = EXCLUDED.current_epoch,
		ca_key_handle = EXCLUDED.ca_key_handle, ca_cert_der = EXCLUDED.ca_cert_der,
		updated_at = EXCLUDED.updated_at, source_sequence = EXCLUDED.source_sequence
		WHERE pcas_issuer_authority.source_sequence < EXCLUDED.source_sequence`,
		ev.TenantID, payload.IssuerID, payload.IdentityID, int64(payload.CurrentEpoch),
		payload.CAKeyHandle, payload.CACertDER, ev.Time, int64(ev.Sequence))
	if err != nil {
		return fmt.Errorf("pcas issuer: project source event: %w", err)
	}
	return nil
}
