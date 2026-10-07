// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func caHorizonEventID(tenantID, authorityID string, band int) string {
	return "ca-horizon:" + tenantID + ":" + authorityID + ":" + strconv.Itoa(band)
}

// RecordCAAuthorityHorizonAlert puts the audit decision in JetStream before a
// PostgreSQL stamp or notification intent can commit. The event is the replay
// authority for both, including an append-then-SQL crash. A deterministic ID
// and canonical EventByID lookup protect retries beyond JetStream's duplicate
// window from producing two audit decisions for the same authority/band.
func (o *Orchestrator) RecordCAAuthorityHorizonAlert(
	ctx context.Context, tenantID string, decision projections.CAAuthorityHorizonAlerted,
) error {
	if o.log == nil || o.store == nil || o.proj == nil || o.outbox == nil {
		return fmt.Errorf("orchestrator: CA horizon command rails are incomplete")
	}
	if err := projections.ValidateCAAuthorityHorizonAlerted(decision); err != nil {
		return err
	}
	payload, err := json.Marshal(decision)
	if err != nil {
		return err
	}
	eventID := caHorizonEventID(tenantID, decision.CAAuthorityID, decision.HorizonMonths)
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		canonical, found, err := o.log.EventByID(ctx, eventID)
		if err != nil {
			return err
		}
		if !found {
			canonical, err = o.log.Append(ctx, events.Event{
				ID: eventID, Type: projections.EventCAAuthorityHorizonAlerted,
				SchemaVersion: projections.CAAuthorityHorizonAlertEventSchemaVersion,
				TenantID:      tenantID, Data: payload,
			})
			if err != nil {
				return err
			}
		}
		entry, err := caHorizonOutboxEntry(canonical)
		if err != nil {
			return err
		}
		if canonical.ID != eventID || canonical.TenantID != tenantID ||
			entry.IdempotencyKey != "ca-horizon:"+decision.CAAuthorityID+":"+strconv.Itoa(decision.HorizonMonths) {
			return fmt.Errorf("%w: canonical CA horizon event differs from requested authority/band", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, canonical); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, entry)
		return err
	})
}

func caHorizonOutboxEntry(event events.Event) (Entry, error) {
	if event.Type != projections.EventCAAuthorityHorizonAlerted ||
		event.SchemaVersion != projections.CAAuthorityHorizonAlertEventSchemaVersion {
		return Entry{}, fmt.Errorf("orchestrator: CA horizon event has no replayable notification command")
	}
	var decision projections.CAAuthorityHorizonAlerted
	if err := json.Unmarshal(event.Data, &decision); err != nil {
		return Entry{}, fmt.Errorf("orchestrator: decode CA horizon event: %w", err)
	}
	if err := projections.ValidateCAAuthorityHorizonAlerted(decision); err != nil {
		return Entry{}, err
	}
	if event.ID != caHorizonEventID(event.TenantID, decision.CAAuthorityID, decision.HorizonMonths) {
		return Entry{}, fmt.Errorf("orchestrator: CA horizon event ID does not bind the tenant, authority and band")
	}
	band, dependents := decision.HorizonMonths, decision.DependentCertificates
	alert := notify.Alert{
		Kind: decision.AlertKind, TenantID: event.TenantID,
		AuthorityID: decision.CAAuthorityID, AuthorityKind: decision.Kind,
		Subject: decision.CommonName, NotAfter: decision.NotAfter,
		Detail: decision.AlertDetail, Severity: decision.Severity,
		HorizonMonths: &band, RenewBy: decision.RenewBy,
		DependentCertificates: &dependents,
	}
	payload, err := json.Marshal(alert)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		TenantID: event.TenantID, Destination: notify.DestinationCAHorizon,
		IdempotencyKey: "ca-horizon:" + decision.CAAuthorityID + ":" + strconv.Itoa(band),
		Payload:        payload,
	}, nil
}
