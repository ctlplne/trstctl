// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RecordEndpointVerification shares certificate metadata admission with issuance
// and revocation. The observation can supersede discovered certificates, so its
// append and projection must finish before a later certificate writer proceeds.
func (o *Orchestrator) RecordEndpointVerification(ctx context.Context, tenantID string, observation projections.EndpointVerificationObserved) error {
	return o.recordEndpointVerification(ctx, tenantID, "", observation)
}

// RecordEndpointVerificationWithEventID retains one observation across retries
// of the same signed claim. Exact event matching refuses changed evidence while
// the shared metadata fence preserves append/projection ordering.
func (o *Orchestrator) RecordEndpointVerificationWithEventID(ctx context.Context, tenantID, eventID string, observation projections.EndpointVerificationObserved) error {
	if strings.TrimSpace(eventID) == "" {
		return errors.New("orchestrator: endpoint verification event id is required")
	}
	return o.recordEndpointVerification(ctx, tenantID, eventID, observation)
}

// The SQL projection and notification intent share one commit. NATS retains
// the signed observation and alert snapshot if that transaction fails.
func (o *Orchestrator) recordEndpointVerification(ctx context.Context, tenantID, eventID string, observation projections.EndpointVerificationObserved) error {
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := o.store.LockCertificateMetadataOrderTx(ctx, tx, tenantID); err != nil {
			return err
		}
		candidate := projections.EndpointVerificationObservedWithAlert{
			EndpointVerificationObserved: observation,
			AlertRequired:                !observation.Reached || observation.Mismatch != "",
		}
		if candidate.AlertRequired {
			lastGood, err := o.store.EndpointVerificationLastGoodTx(ctx, tx, tenantID, observation.EndpointID, observation.Vantage)
			if err != nil {
				return err
			}
			candidate.AlertLastGoodAt = lastGood
		}
		payload, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		ev, err := o.log.Append(ctx, events.Event{ID: eventID, TenantID: tenantID,
			Type: projections.EventEndpointVerified, SchemaVersion: projections.EndpointVerificationAlertEventSchemaVersion, Data: payload})
		if err != nil {
			return err
		}
		retained, err := retainedEndpointVerification(ev, tenantID, eventID, observation)
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		_, err = o.enqueueEndpointVerificationAlertTx(ctx, tx, tenantID, retained)
		return err
	})
}

// Only the server-owned last-good snapshot may differ on a retry. Preserve the
// first event's snapshot, and require every signed observation field to match.
func retainedEndpointVerification(ev events.Event, tenantID, eventID string, expected projections.EndpointVerificationObserved) (projections.EndpointVerificationObservedWithAlert, error) {
	var retained projections.EndpointVerificationObservedWithAlert
	if (eventID != "" && ev.ID != eventID) || ev.TenantID != tenantID || ev.Type != projections.EventEndpointVerified || ev.SchemaVersion != projections.EndpointVerificationAlertEventSchemaVersion {
		return retained, fmt.Errorf("%w: endpoint observation event binding differs", store.ErrIdempotencyConflict)
	}
	if err := json.Unmarshal(ev.Data, &retained); err != nil {
		return retained, err
	}
	want, err := json.Marshal(expected)
	if err != nil {
		return retained, err
	}
	got, err := json.Marshal(retained.EndpointVerificationObserved)
	if err != nil {
		return retained, err
	}
	if !bytes.Equal(want, got) {
		return retained, fmt.Errorf("%w: canonical endpoint observation differs", store.ErrIdempotencyConflict)
	}
	return retained, retained.ValidateAlert()
}
