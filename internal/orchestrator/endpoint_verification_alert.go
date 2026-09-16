// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
)

// Only immutable incident fields enter the deduplication identity. Repeated
// failed probes do not page once per sweep; a successful probe advances the
// last-good snapshot, so the next outage has a distinct notification identity.
func endpointVerificationAlertEntry(tenantID string, v projections.EndpointVerificationObservedWithAlert) (Entry, error) {
	if err := v.ValidateAlert(); err != nil {
		return Entry{}, err
	}
	if !v.AlertRequired {
		return Entry{}, nil
	}
	identity, err := json.Marshal(struct {
		TenantID, EndpointID, Address, Vantage, Expected, Observed, Mismatch string
		LastGoodAt                                                           time.Time
	}{tenantID, v.EndpointID, v.Address, v.Vantage, v.ExpectedFingerprint, v.ObservedFingerprint, v.Mismatch, v.AlertLastGoodAt})
	if err != nil {
		return Entry{}, err
	}
	key := "endpoint-verify:v2:" + crypto.SHA256Hex(identity)
	kind, severity := notify.KindEndpointVerificationFailed, notify.AlertSeverityCritical
	detail := "Certificate verification failed at the endpoint. Open its verification details."
	if !v.Reached {
		kind, severity = notify.KindEndpointUnreachable, notify.AlertSeverityWarning
		detail = "Verification could not reach the endpoint. Check its listener and the probe's network path."
	} else if v.AlertLastGoodAt.IsZero() {
		detail += " This endpoint has never been observed serving the expected identity."
	}
	// Agent-supplied error wording changes between probes of the same outage.
	// Keep it in the observation; the queued alert uses stable incident wording.
	payload, err := json.Marshal(notify.Alert{
		Kind: kind, TenantID: tenantID, OperationID: key, Severity: severity,
		EndpointAddress: v.Address, Vantage: v.Vantage, Mismatch: v.Mismatch,
		LastGoodAt: v.AlertLastGoodAt, Subject: v.Address, Detail: detail,
	})
	if err != nil {
		return Entry{}, err
	}
	return Entry{TenantID: tenantID, Destination: notify.DestinationVerification, IdempotencyKey: key, Payload: payload}, nil
}

func (o *Orchestrator) enqueueEndpointVerificationAlertTx(ctx context.Context, tx pgx.Tx, tenantID string, v projections.EndpointVerificationObservedWithAlert) (bool, error) {
	entry, err := endpointVerificationAlertEntry(tenantID, v)
	if err != nil || entry.Destination == "" {
		return false, err
	}
	if o.outbox == nil {
		return false, errors.New("orchestrator: endpoint verification alert outbox is unavailable")
	}
	return o.outbox.EnqueueIfAbsent(ctx, tx, entry)
}

func (o *Orchestrator) reconcileEndpointVerificationAlert(ctx context.Context, ev events.Event) (int, error) {
	if err := projections.ValidateSchemaVersion(ev); err != nil {
		return 0, err
	}
	// Legacy observations did not authorize a durable notification. Do not
	// invent historical alerts during an upgrade or projection reconstruction.
	if ev.SchemaVersion != projections.EndpointVerificationAlertEventSchemaVersion {
		return 0, nil
	}
	var observed projections.EndpointVerificationObservedWithAlert
	if err := json.Unmarshal(ev.Data, &observed); err != nil {
		return 0, fmt.Errorf("decode retained endpoint verification alert: %w", err)
	}
	var inserted bool
	err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		var err error
		inserted, err = o.enqueueEndpointVerificationAlertTx(ctx, tx, ev.TenantID, observed)
		return err
	})
	if inserted {
		return 1, err
	}
	return 0, err
}
