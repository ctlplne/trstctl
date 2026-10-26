// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	corestore "trstctl.com/trstctl/internal/store"
)

// Attestor is a tenant-registered attestation verifier key: the public half of
// the key that signs the tenant's attestation evidence, bound to the one
// attestation method that evidence is for.
type Attestor struct {
	KeyID     string
	Method    string
	PublicDER []byte
	CreatedAt time.Time
}

// AttestorProjection rebuilds the tenant attestor registry from its source
// events, joining the generic projector transaction like the root-anchor
// registry so a failed replay cannot leave half a registry.
type AttestorProjection struct{ store *corestore.Store }

func NewAttestorProjection(store *corestore.Store) *AttestorProjection {
	return &AttestorProjection{store: store}
}

func (*AttestorProjection) Name() string             { return "agentid.attestor" }
func (*AttestorProjection) ProjectsTenantLifecycle() {}

func (p *AttestorProjection) Reset(ctx context.Context) error {
	if p == nil || p.store == nil {
		return errors.New("agentid attestor: projection store unavailable")
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

func (p *AttestorProjection) ResetTx(ctx context.Context, tx pgx.Tx) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("agentid attestor: projection transaction unavailable")
	}
	//trstctl:system-query — cross-tenant full rebuild uses a system transaction to clear only the derived attestor registry; tenant-bound immutable events restore it under RLS.
	_, err := tx.Exec(ctx, `DELETE FROM agent_attestors`)
	return err
}

func (p *AttestorProjection) Apply(ctx context.Context, ev eventspec.Event) error {
	if ev.Type != delegation.TypeAttestorRegistered && ev.Type != tenantOffboardedEvent {
		return nil
	}
	if p == nil || p.store == nil {
		return errors.New("agentid attestor: projection store unavailable")
	}
	return p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		return p.ApplyTx(ctx, tx, ev)
	})
}

func (p *AttestorProjection) ApplyTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("agentid attestor: projection transaction unavailable")
	}
	if ev.Type != delegation.TypeAttestorRegistered && ev.Type != tenantOffboardedEvent {
		return nil
	}
	if err := p.store.SetTenantGUCTx(ctx, tx, ev.TenantID); err != nil {
		return err
	}
	if ev.Type == tenantOffboardedEvent {
		_, err := tx.Exec(ctx, `DELETE FROM agent_attestors WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`)
		return err
	}
	decoded, err := delegation.Decode(ev)
	if err != nil {
		return err
	}
	payload, ok := decoded.(delegation.AttestorRegisteredV1)
	if !ok {
		return nil // a newer schema cannot project current trust history
	}
	if payload.TenantID != ev.TenantID || !delegation.ValidRootAnchorID(payload.KeyID) ||
		ev.ID != delegation.AttestorEventID(ev.TenantID, payload.KeyID) ||
		delegation.ClassOfMethod(payload.Method) == delegation.ClassNone || ev.Time.IsZero() {
		return errors.New("agentid attestor: invalid event authority binding")
	}
	if err := crypto.ValidatePublicKeyDER(payload.PublicDER); err != nil {
		return fmt.Errorf("agentid attestor: invalid event public key: %w", err)
	}
	var inserted int
	err = tx.QueryRow(ctx, `INSERT INTO agent_attestors
		(tenant_id, key_id, method, public_der, created_at)
		VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4)
		ON CONFLICT (tenant_id, key_id) DO NOTHING RETURNING 1`,
		payload.KeyID, payload.Method, payload.PublicDER, ev.Time).Scan(&inserted)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("agentid attestor: project attestor binding: %w", err)
	}
	var existingMethod string
	var existingDER []byte
	if err := tx.QueryRow(ctx, `SELECT method, public_der FROM agent_attestors
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND key_id = $1`, payload.KeyID).
		Scan(&existingMethod, &existingDER); err != nil {
		return fmt.Errorf("agentid attestor: read first writer: %w", err)
	}
	if existingMethod != payload.Method || !bytes.Equal(existingDER, payload.PublicDER) {
		return fmt.Errorf("agentid attestor: key ID belongs to another attestor binding: %w", corestore.ErrIdempotencyConflict)
	}
	return nil
}

func (p *AttestorProjection) ReplayTenantLifecycleTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	return p.ApplyTx(ctx, tx, ev)
}

// ApplyAttestorEvent projects one recorded attestor event synchronously, so the
// registering request reads its own write.
func (r *Repo) ApplyAttestorEvent(ctx context.Context, ev eventspec.Event) error {
	return NewAttestorProjection(r.core).Apply(ctx, ev)
}

// ListAttestors returns the caller tenant's registered attestors ordered by key ID.
func (r *Repo) ListAttestors(ctx context.Context, tenantID string) ([]Attestor, error) {
	var out []Attestor
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT key_id, method, public_der, created_at
			   FROM agent_attestors
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			  ORDER BY key_id ASC`)
		if err != nil {
			return fmt.Errorf("agid store: list attestors: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var a Attestor
			if err := rows.Scan(&a.KeyID, &a.Method, &a.PublicDER, &a.CreatedAt); err != nil {
				return fmt.Errorf("agid store: scan attestor: %w", err)
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
