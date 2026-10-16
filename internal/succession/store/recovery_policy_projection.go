// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/recovery"
)

// RecoveryPolicyProjection rebuilds public recovery authority from the event
// log. Legacy rows without a source sequence are not authority until explicitly
// reconfigured through the API.
type RecoveryPolicyProjection struct{ store *corestore.Store }

func NewRecoveryPolicyProjection(store *corestore.Store) *RecoveryPolicyProjection {
	return &RecoveryPolicyProjection{store: store}
}

func (*RecoveryPolicyProjection) Name() string             { return "pcas.recovery.policy" }
func (*RecoveryPolicyProjection) ProjectsTenantLifecycle() {}

func (p *RecoveryPolicyProjection) Reset(ctx context.Context) error {
	return p.withSystemTx(ctx, func(tx pgx.Tx) error { return p.ResetTx(ctx, tx) })
}

func (p *RecoveryPolicyProjection) Apply(ctx context.Context, ev eventspec.Event) error {
	if ev.Type != succession.TypeRecoveryPolicyConfigured && ev.Type != projections.EventTenantOffboarded {
		return nil
	}
	if p == nil || p.store == nil {
		return errors.New("pcas recovery policy: projection store unavailable")
	}
	if ev.Type == projections.EventTenantOffboarded {
		return p.withSystemTx(ctx, func(tx pgx.Tx) error { return p.ApplyTx(ctx, tx, ev) })
	}
	return p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error { return p.ApplyTx(ctx, tx, ev) })
}

func (p *RecoveryPolicyProjection) withSystemTx(ctx context.Context, apply func(pgx.Tx) error) error {
	if p == nil || p.store == nil {
		return errors.New("pcas recovery policy: projection store unavailable")
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

func (p *RecoveryPolicyProjection) ResetTx(ctx context.Context, tx pgx.Tx) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("pcas recovery policy: projection store unavailable")
	}
	//trstctl:system-query — an explicit full replay resets this derived table and reapplies tenant-bound source events.
	_, err := tx.Exec(ctx, `DELETE FROM pcas_recovery_policy`)
	return err
}

func (p *RecoveryPolicyProjection) ApplyTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("pcas recovery policy: projection store unavailable")
	}
	if ev.Type == projections.EventTenantOffboarded {
		_, err := tx.Exec(ctx, `DELETE FROM pcas_recovery_policy WHERE tenant_id = $1`, ev.TenantID)
		return err
	}
	if ev.Type != succession.TypeRecoveryPolicyConfigured {
		return nil
	}
	return ApplyRecoveryPolicyEventTx(ctx, tx, ev)
}

func (p *RecoveryPolicyProjection) ReplayTenantLifecycleTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	return p.ApplyTx(ctx, tx, ev)
}

// ApplyRecoveryPolicyEventTx uses the log sequence as the first-writer fence.
// Delayed or duplicate delivery cannot replace a newer tenant policy.
func ApplyRecoveryPolicyEventTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Type != succession.TypeRecoveryPolicyConfigured || ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return errors.New("pcas recovery policy: invalid source event")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	payload, ok := decoded.(succession.RecoveryPolicyConfiguredV1)
	if !ok {
		return nil // future schema is never interpreted as current authority
	}
	if payload.TenantID != ev.TenantID || strings.TrimSpace(payload.IdentityID) == "" || strings.TrimSpace(payload.IdentityID) != payload.IdentityID {
		return errors.New("pcas recovery policy: event tenant or identity mismatch")
	}
	var roster []recovery.Approver
	if err := json.Unmarshal(payload.Roster, &roster); err != nil {
		return fmt.Errorf("pcas recovery policy: decode roster: %w", err)
	}
	if err := recovery.ValidatePolicy(recovery.Policy{TrustRootDER: payload.TrustRootDER, Threshold: payload.Threshold, Roster: roster}); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO pcas_recovery_policy
		(tenant_id, identity_id, threshold, roster_json, trust_root_der, updated_at, source_sequence)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7)
		ON CONFLICT (tenant_id, identity_id) DO UPDATE SET
		threshold = EXCLUDED.threshold, roster_json = EXCLUDED.roster_json,
		trust_root_der = EXCLUDED.trust_root_der, updated_at = EXCLUDED.updated_at,
		source_sequence = EXCLUDED.source_sequence
		WHERE pcas_recovery_policy.source_sequence < EXCLUDED.source_sequence`,
		ev.TenantID, payload.IdentityID, payload.Threshold, payload.Roster,
		payload.TrustRootDER, ev.Time, int64(ev.Sequence))
	if err != nil {
		return fmt.Errorf("pcas recovery policy: project event: %w", err)
	}
	return nil
}
