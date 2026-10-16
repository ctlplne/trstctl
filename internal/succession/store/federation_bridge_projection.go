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

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/federation"
)

// FederationBridgeProjection serves only signed bridges backed by immutable
// tenant events. A queued command or an older direct-write row is not authority.
type FederationBridgeProjection struct{ store *corestore.Store }

func NewFederationBridgeProjection(store *corestore.Store) *FederationBridgeProjection {
	return &FederationBridgeProjection{store: store}
}

func (*FederationBridgeProjection) Name() string             { return "pcas.federation.bridge" }
func (*FederationBridgeProjection) ProjectsTenantLifecycle() {}

func (p *FederationBridgeProjection) Reset(ctx context.Context) error {
	return p.withSystemTx(ctx, func(tx pgx.Tx) error { return p.ResetTx(ctx, tx) })
}

func (p *FederationBridgeProjection) Apply(ctx context.Context, ev eventspec.Event) error {
	if ev.Type != succession.TypeFederationBridgeImported && ev.Type != projections.EventTenantOffboarded {
		return nil
	}
	if p == nil || p.store == nil {
		return errors.New("pcas federation: projection store unavailable")
	}
	if ev.Type == projections.EventTenantOffboarded {
		return p.withSystemTx(ctx, func(tx pgx.Tx) error { return p.ApplyTx(ctx, tx, ev) })
	}
	return p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error { return p.ApplyTx(ctx, tx, ev) })
}

func (p *FederationBridgeProjection) withSystemTx(ctx context.Context, apply func(pgx.Tx) error) error {
	if p == nil || p.store == nil {
		return errors.New("pcas federation: projection store unavailable")
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

func (p *FederationBridgeProjection) ResetTx(ctx context.Context, tx pgx.Tx) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("pcas federation: projection store unavailable")
	}
	//trstctl:system-query — full replay resets only this derived bridge table.
	_, err := tx.Exec(ctx, `DELETE FROM pcas_federation_bridge`)
	return err
}

func (p *FederationBridgeProjection) ApplyTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("pcas federation: projection store unavailable")
	}
	if ev.Type == projections.EventTenantOffboarded {
		_, err := tx.Exec(ctx, `DELETE FROM pcas_federation_bridge WHERE tenant_id = $1`, ev.TenantID)
		return err
	}
	if ev.Type != succession.TypeFederationBridgeImported {
		return nil
	}
	return ApplyFederationBridgeEventTx(ctx, tx, ev)
}

func (p *FederationBridgeProjection) ReplayTenantLifecycleTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	return p.ApplyTx(ctx, tx, ev)
}

// ApplyFederationBridgeEventTx re-verifies the signed public proof and fences
// delayed events by source sequence. The projection never signs or trusts a
// request field alone.
func ApplyFederationBridgeEventTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Type != succession.TypeFederationBridgeImported || ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return errors.New("pcas federation: invalid source event")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	payload, ok := decoded.(succession.FederationBridgeImportedV1)
	if !ok {
		return nil
	}
	if payload.TenantID != ev.TenantID || strings.TrimSpace(payload.RequestID) == "" ||
		strings.TrimSpace(payload.ForeignDeploymentID) == "" ||
		strings.TrimSpace(payload.LocalDeploymentID) == "" ||
		strings.TrimSpace(payload.IdentityID) == "" || payload.LocalBaseEpoch > math.MaxInt64 ||
		len(payload.RequestDigest) != 32 {
		return errors.New("pcas federation: source event binding is invalid")
	}
	if err := crypto.ValidatePublicKeyDER(payload.ForeignTrustRootDER); err != nil {
		return fmt.Errorf("pcas federation: source foreign root: %w", err)
	}
	if err := crypto.ValidatePublicKeyDER(payload.LocalAuthorityPublicDER); err != nil {
		return fmt.Errorf("pcas federation: source local authority: %w", err)
	}
	var bridge federation.BridgeRecord
	if err := json.Unmarshal(payload.Bridge, &bridge); err != nil {
		return fmt.Errorf("pcas federation: source bridge: %w", err)
	}
	if bridge.ForeignDeployment != payload.ForeignDeploymentID ||
		bridge.LocalDeployment != payload.LocalDeploymentID ||
		bridge.IdentityID != payload.IdentityID || bridge.LocalBaseEpoch != payload.LocalBaseEpoch {
		return errors.New("pcas federation: signed bridge and source event disagree")
	}
	if err := federation.VerifyBridge(payload.LocalAuthorityPublicDER, nil, bridge, false); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO pcas_federation_bridge
		(tenant_id, foreign_deployment_id, identity_id, foreign_trust_root_der,
		 local_base_epoch, bridge_json, updated_at, source_sequence)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
		ON CONFLICT (tenant_id, foreign_deployment_id, identity_id) DO UPDATE SET
		foreign_trust_root_der = EXCLUDED.foreign_trust_root_der,
		local_base_epoch = EXCLUDED.local_base_epoch, bridge_json = EXCLUDED.bridge_json,
		updated_at = EXCLUDED.updated_at, source_sequence = EXCLUDED.source_sequence
		WHERE pcas_federation_bridge.source_sequence < EXCLUDED.source_sequence`,
		ev.TenantID, payload.ForeignDeploymentID, payload.IdentityID,
		payload.ForeignTrustRootDER, int64(payload.LocalBaseEpoch), payload.Bridge,
		ev.Time, int64(ev.Sequence))
	if err != nil {
		return fmt.Errorf("pcas federation: project verified bridge: %w", err)
	}
	return nil
}
