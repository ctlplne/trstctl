// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// The explicitly configured evaluation tenant needs the same durable lifecycle
// as a CLI- or provider-created tenant. An SSO claim only scopes a principal; it
// does not register a tenant. Production and arbitrary IdP claims never enter
// this path. Existing registrations are verified, never renamed or recreated.
func ensureEvalTenantRegistration(ctx context.Context, d Deps) error {
	if d.Protocols.Profile != config.ProtocolProfileEval {
		return nil
	}
	tenantID := d.Protocols.EvalTenantID
	if _, err := d.Store.GetTenant(ctx, tenantID); err == nil {
		_, err = orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, d.Log, d.Store, tenantID)
		return err
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	const name = "Evaluation"
	payload, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: name})
	if err != nil {
		return err
	}
	_, err = orchestrator.ExecuteTenantRegistration(ctx, d.Log, d.Store, projections.New(d.Store),
		orchestrator.NewIdempotency(d.Store, orchestrator.WithResultProtector(d.IdempotencyResultProtector)),
		orchestrator.TenantRegistrationCommand{
			TenantID: tenantID, Name: name, IdempotencyKey: "eval-tenant:" + tenantID,
			InitialOnly: true, RequestMaterial: payload,
			PayloadAt: func(time.Time) ([]byte, error) { return append([]byte(nil), payload...), nil },
		})
	if err != nil {
		return fmt.Errorf("register configured evaluation tenant: %w", err)
	}
	// Owner decision 2026-10-24: new tenants start with control-plane key
	// generation off. The evaluation preset turns the compatibility Workload API
	// socket on, so its tenant starts on, and the decision says why.
	if _, err := orchestrator.NewOrchestrator(d.Log, d.Store, nil).SetControlPlaneKeygen(ctx, tenantID, projections.ControlPlaneKeygenSet{
		Enabled: true, Source: store.ControlPlaneKeygenSourceRegistration,
		Reason: "evaluation preset: the compatibility Workload API socket is on",
	}); err != nil {
		return fmt.Errorf("record the evaluation tenant's key generation default: %w", err)
	}
	return nil
}
