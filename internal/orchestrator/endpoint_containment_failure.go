// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// RecordEndpointContainmentFailure makes one signed non-stopped host result
// and its operator notification durable together. A retry after the NATS
// append uses the same event ID and reconstructs the missing SQL projection
// and outbox intent; it cannot silently create a different incident.
func (o *Orchestrator) RecordEndpointContainmentFailure(ctx context.Context,
	tenantID, eventID string, r store.ConnectorDeliveryReceipt) (store.ConnectorDeliveryReceipt, error) {
	if eventID == "" || r.ID == "" || r.OutboxID == nil || r.IdentityID == nil ||
		r.Destination != DestinationEndpointContainment || !containmentNeedsAlert(r.Status) ||
		r.Fingerprint == "" {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: containment failure needs an exact receipt, job, identity and leaf")
	}
	pl := projections.ConnectorDeliveryRecorded{
		ID: r.ID, OutboxID: r.OutboxID, IdentityID: r.IdentityID,
		Destination: r.Destination, Connector: r.Connector, Target: r.Target,
		Fingerprint: r.Fingerprint, Status: r.Status, Attempts: r.Attempts,
		Reason: r.Reason, Detail: r.Detail, IdempotencyKey: r.IdempotencyKey,
	}
	payload, err := json.Marshal(pl)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	var retained events.Event
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if o.outbox == nil {
			return errors.New("orchestrator: containment notification outbox is unavailable")
		}
		var err error
		retained, err = o.log.Append(ctx, events.Event{ID: eventID,
			Type: projections.EventConnectorDeliveryRecorded, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if retained.ID != eventID || retained.TenantID != tenantID ||
			retained.Type != projections.EventConnectorDeliveryRecorded || !bytes.Equal(retained.Data, payload) {
			return fmt.Errorf("%w: containment failure event differs from retained receipt", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, retained); err != nil {
			return err
		}
		entry, err := endpointContainmentFailureAlertEntry(tenantID, pl)
		if err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, entry)
		return err
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	r.TenantID, r.EventSequence = tenantID, retained.Sequence
	r.CreatedAt, r.UpdatedAt = retained.Time, retained.Time
	return r, nil
}

func endpointContainmentFailureAlertEntry(tenantID string, pl projections.ConnectorDeliveryRecorded) (Entry, error) {
	if tenantID == "" || pl.ID == "" || pl.OutboxID == nil || pl.IdentityID == nil ||
		pl.Destination != DestinationEndpointContainment || !containmentNeedsAlert(pl.Status) {
		return Entry{}, errors.New("orchestrator: containment failure alert has no exact failed job")
	}
	key := "containment-failed:" + pl.ID
	payload, err := json.Marshal(notify.Alert{
		Kind: notify.KindEndpointContainmentFailed, TenantID: tenantID,
		OperationID: key, IdentityID: *pl.IdentityID, Subject: pl.Target,
		Severity: notify.AlertSeverityCritical, CertificateFingerprint: pl.Fingerprint,
		DeploymentReceiptID: pl.ID,
		Detail:              "The host did not prove that the named certificate stopped serving. Inspect the signed containment receipt and listener. Correct the host profile or service, then review a fresh containment preview and submit a new idempotency key. Publish and verify CA revocation separately.",
	})
	if err != nil {
		return Entry{}, err
	}
	return Entry{TenantID: tenantID, Destination: notify.DestinationContainment,
		IdempotencyKey: key, Payload: payload}, nil
}

// The event log remains the recovery source if a process dies after append but
// before PostgreSQL commits the failure receipt and notification together.
func (o *Orchestrator) reconcileEndpointContainmentFailureAlert(ctx context.Context, ev events.Event) (int, error) {
	if err := projections.ValidateSchemaVersion(ev); err != nil {
		return 0, err
	}
	var pl projections.ConnectorDeliveryRecorded
	if err := json.Unmarshal(ev.Data, &pl); err != nil {
		return 0, err
	}
	if pl.Destination != DestinationEndpointContainment || !containmentNeedsAlert(pl.Status) {
		return 0, nil
	}
	entry, err := endpointContainmentFailureAlertEntry(ev.TenantID, pl)
	if err != nil {
		return 0, err
	}
	var inserted bool
	err = o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		var err error
		inserted, err = o.outbox.EnqueueIfAbsent(ctx, tx, entry)
		return err
	})
	if inserted {
		return 1, err
	}
	return 0, err
}

func containmentNeedsAlert(status string) bool {
	switch status {
	case servedstatus.ConnectorContainmentFailed,
		servedstatus.ConnectorContainmentUnverified,
		servedstatus.ConnectorContainmentDifferentLeaf:
		return true
	default:
		return false
	}
}
