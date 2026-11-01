// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RegisterDecoySecret makes a stored application secret a decoy (Q6). The
// secret itself is an ordinary secret, written through the normal create path,
// so nothing a reader can see tells it apart; only the decoy registry, readable
// by those who may plant decoys, knows.
func (o *Orchestrator) RegisterDecoySecret(ctx context.Context, tenantID, name, placement, secretName string) (store.HoneyToken, error) {
	id := uuid.NewString()
	payload, err := json.Marshal(projections.HoneyTokenCreated{
		ID: id, Name: name, Placement: placement, TokenHash: "secret-decoy:" + id, SecretName: secretName,
	})
	if err != nil {
		return store.HoneyToken{}, err
	}
	if _, err := o.emit(ctx, projections.EventHoneyTokenCreated, tenantID, payload); err != nil {
		return store.HoneyToken{}, err
	}
	return o.store.GetHoneyToken(ctx, tenantID, id)
}

// RecordDecoySecretRead records that reader read a decoy secret's value. The
// projection keeps the first reader and alerts once per distinct reader.
func (o *Orchestrator) RecordDecoySecretRead(ctx context.Context, tenantID, id, reader, method, path string) error {
	payload, err := json.Marshal(projections.HoneyTokenTriggered{ID: id, Method: method, Path: path, Reader: reader})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventHoneyTokenTriggered, tenantID, payload)
	return err
}

// RegisterDatabaseDecoy records a decoy PostgreSQL login minted by a tenant's
// dynamic-secret provider (Q6). The lease owns the login; the decoy names it so
// the leader's watcher can read its database's session counter.
func (o *Orchestrator) RegisterDatabaseDecoy(ctx context.Context, tenantID, name, placement, providerID, leaseID, role string) (store.HoneyToken, error) {
	id := uuid.NewString()
	payload, err := json.Marshal(projections.HoneyTokenCreated{
		ID: id, Name: name, Placement: placement, TokenHash: "database-decoy:" + id,
		DBProviderID: providerID, DBLeaseID: leaseID, DBRole: role,
	})
	if err != nil {
		return store.HoneyToken{}, err
	}
	if _, err := o.emit(ctx, projections.EventHoneyTokenCreated, tenantID, payload); err != nil {
		return store.HoneyToken{}, err
	}
	return o.store.GetHoneyToken(ctx, tenantID, id)
}
