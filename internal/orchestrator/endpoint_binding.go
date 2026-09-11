// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// BindIdentityEndpoint records the reviewed issuer and destination together.
// Hold the identity lock from validation through append and projection so a
// concurrent issuance cannot win between validation and authority selection.
func (o *Orchestrator) BindIdentityEndpoint(ctx context.Context, tenantID, identityID string, target store.DeploymentTarget, issuer store.IdentityEndpointIssuer) (store.Identity, error) {
	if target.ID == "" || target.Type == "" || target.Name == "" || len(issuer.PreviewFingerprint) != 64 {
		return store.Identity{}, fmt.Errorf("%w: destination and reviewed fingerprint are required", store.ErrIdentityEnrollmentConflict)
	}
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		identity, _, err := o.store.IdentityApprovalTargetTx(ctx, tx, tenantID, identityID, true)
		if err != nil {
			return err
		}
		if err := store.ValidateIdentityEndpointIssuer(identity, issuer); err != nil {
			return err
		}
		payload, err := json.Marshal(projections.IdentityConnectorTargetBound{
			IdentityID: identityID, TargetID: target.ID, Connector: target.Type, Target: target.Name,
			Route: deploymentRoute(target), Issuer: &issuer,
		})
		if err != nil {
			return err
		}
		ev, err := o.log.Append(ctx, events.Event{Type: projections.EventIdentityConnectorTargetBound,
			TenantID: tenantID, SchemaVersion: 2, Data: payload})
		if err != nil {
			return err
		}
		return o.proj.ApplyTx(ctx, tx, ev)
	})
	if err != nil {
		return store.Identity{}, err
	}
	return o.store.GetIdentity(ctx, tenantID, identityID)
}
