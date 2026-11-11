// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// CreateHoneyToken mints an inert bait bearer. Only its one-way hash enters the
// event stream and projection; the raw bytes belong to the caller until written
// in the one-time API response.
func (o *Orchestrator) CreateHoneyToken(ctx context.Context, tenantID, name, placement string) (store.HoneyToken, []byte, error) {
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		return store.HoneyToken{}, nil, err
	}
	id := uuid.NewString()
	payload, err := json.Marshal(projections.HoneyTokenCreated{ID: id, Name: name, Placement: placement, TokenHash: hash})
	if err != nil {
		secret.Wipe(raw)
		return store.HoneyToken{}, nil, err
	}
	ev, err := o.emit(ctx, projections.EventHoneyTokenCreated, tenantID, payload)
	if err != nil {
		secret.Wipe(raw)
		return store.HoneyToken{}, nil, err
	}
	return store.HoneyToken{
		ID: id, TenantID: tenantID, Name: name, Placement: placement,
		TokenHash: hash, State: "active", CreatedAt: ev.Time,
	}, raw, nil
}

// RecordHoneyTokenTrigger never authenticates the bearer. The projection puts
// the first trigger and its alert in one PostgreSQL transaction.
func (o *Orchestrator) RecordHoneyTokenTrigger(ctx context.Context, tenantID, id, method, path string) error {
	payload, err := json.Marshal(projections.HoneyTokenTriggered{ID: id, Method: method, Path: path})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventHoneyTokenTriggered, tenantID, payload)
	return err
}

// OpenHoneyTokenWatchGap records that the watcher has not been able to read a
// decoy login since since, and why (Q6-L10); the projection alerts once.
func (o *Orchestrator) OpenHoneyTokenWatchGap(ctx context.Context, tenantID, id, reason string, since time.Time) error {
	if len(reason) > 512 {
		reason = reason[:512]
	}
	payload, err := json.Marshal(projections.HoneyTokenWatchGapOpened{ID: id, Reason: reason, Since: since.UTC()})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventHoneyTokenWatchGapOpened, tenantID, payload)
	return err
}

// CloseHoneyTokenWatchGap records that the watcher reads the decoy again.
func (o *Orchestrator) CloseHoneyTokenWatchGap(ctx context.Context, tenantID, id string) error {
	payload, err := json.Marshal(projections.HoneyTokenWatchGapClosed{ID: id})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventHoneyTokenWatchGapClosed, tenantID, payload)
	return err
}

func (o *Orchestrator) RevokeHoneyToken(ctx context.Context, tenantID, id string) error {
	payload, err := json.Marshal(projections.HoneyTokenRevoked{ID: id})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventHoneyTokenRevoked, tenantID, payload)
	return err
}
