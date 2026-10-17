// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	corestore "trstctl.com/trstctl/internal/store"
)

const tenantOffboardedEvent = "tenant.offboarded"

// RootAnchorProjection rebuilds the public tenant trust registry from source
// events. It joins the generic projector transaction so a failed replay cannot
// leave a half-rebuilt root floor.
type RootAnchorProjection struct{ store *corestore.Store }

func NewRootAnchorProjection(store *corestore.Store) *RootAnchorProjection {
	return &RootAnchorProjection{store: store}
}

func (*RootAnchorProjection) Name() string             { return "agentid.root_anchor" }
func (*RootAnchorProjection) ProjectsTenantLifecycle() {}

func (p *RootAnchorProjection) Reset(ctx context.Context) error {
	if p == nil || p.store == nil {
		return errors.New("agentid root: projection store unavailable")
	}
	tx, err := p.store.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.ResetTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *RootAnchorProjection) ResetTx(ctx context.Context, tx pgx.Tx) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("agentid root: projection transaction unavailable")
	}
	//trstctl:system-query — cross-tenant full rebuild uses a system transaction to clear only the derived root registry; tenant-bound immutable events restore it under RLS.
	_, err := tx.Exec(ctx, `DELETE FROM agent_root_anchors`)
	return err
}

func (p *RootAnchorProjection) Apply(ctx context.Context, ev eventspec.Event) error {
	if ev.Type != delegation.TypeRootAnchorRegistered && ev.Type != delegation.TypeRootAnchorUnprovisioned && ev.Type != tenantOffboardedEvent {
		return nil
	}
	if p == nil || p.store == nil {
		return errors.New("agentid root: projection store unavailable")
	}
	return p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		return p.ApplyTx(ctx, tx, ev)
	})
}

func (p *RootAnchorProjection) ApplyTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("agentid root: projection transaction unavailable")
	}
	if ev.Type != delegation.TypeRootAnchorRegistered && ev.Type != delegation.TypeRootAnchorUnprovisioned && ev.Type != tenantOffboardedEvent {
		return nil
	}
	if err := p.store.SetTenantGUCTx(ctx, tx, ev.TenantID); err != nil {
		return err
	}
	if ev.Type == tenantOffboardedEvent {
		_, err := tx.Exec(ctx, `DELETE FROM agent_root_anchors WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`)
		return err
	}
	decoded, err := delegation.Decode(ev)
	if err != nil {
		return err
	}
	var tenantID, keyID, authRef, eventID string
	var publicDER []byte
	switch payload := decoded.(type) {
	case delegation.RootAnchorRegisteredV1:
		tenantID, keyID, authRef, publicDER = payload.TenantID, payload.KeyID, payload.AuthRef, payload.PublicDER
		eventID = delegation.RootAnchorEventID(ev.TenantID, keyID)
	case delegation.RootAnchorUnprovisionedV1:
		if payload.Reason != delegation.RootAnchorUnprovisionedReasonSignerAbsent {
			return errors.New("agentid root: invalid legacy signer-absent reason")
		}
		tenantID, keyID, authRef, publicDER = payload.TenantID, payload.KeyID, payload.AuthRef, payload.PublicDER
		eventID = delegation.RootAnchorUnprovisionedEventID(ev.TenantID, keyID)
	default:
		return nil // a newer schema cannot project current trust history
	}
	if tenantID != ev.TenantID || !delegation.ValidRootAnchorID(keyID) ||
		ev.ID != eventID ||
		authRef == "" || strings.TrimSpace(authRef) != authRef ||
		ev.Time.IsZero() {
		return errors.New("agentid root: invalid event authority binding")
	}
	if err := crypto.ValidatePublicKeyDER(publicDER); err != nil {
		return fmt.Errorf("agentid root: invalid event public key: %w", err)
	}
	var inserted int
	err = tx.QueryRow(ctx, `INSERT INTO agent_root_anchors
		(tenant_id, key_id, public_der, auth_ref, created_at)
		VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4)
		ON CONFLICT (tenant_id, key_id) DO NOTHING RETURNING 1`,
		keyID, publicDER, authRef, ev.Time).Scan(&inserted)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("agentid root: project trust tuple: %w", err)
	}
	var existingDER []byte
	var existingAuthRef string
	if err := tx.QueryRow(ctx, `SELECT public_der, auth_ref FROM agent_root_anchors
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND key_id = $1`, keyID).
		Scan(&existingDER, &existingAuthRef); err != nil {
		return fmt.Errorf("agentid root: read first writer: %w", err)
	}
	if !bytes.Equal(existingDER, publicDER) || existingAuthRef != authRef {
		return fmt.Errorf("agentid root: key ID belongs to another trust tuple: %w", corestore.ErrIdempotencyConflict)
	}
	return nil
}

func (p *RootAnchorProjection) ReplayTenantLifecycleTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	return p.ApplyTx(ctx, tx, ev)
}

func (r *Repo) ApplyRootAnchorEvent(ctx context.Context, ev eventspec.Event) error {
	return NewRootAnchorProjection(r.core).Apply(ctx, ev)
}
