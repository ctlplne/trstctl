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
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/revocationhealth"
	"trstctl.com/trstctl/internal/store"
)

// QueueRevocationProbe commits the immutable bounded relay command and its
// outbox intent together. The supplied UUID is a stable scheduler identity, so
// concurrent replicas converge before any relay can see duplicate work.
func (o *Orchestrator) QueueRevocationProbe(ctx context.Context, tenantID string, intent revocationhealth.Intent) (events.Event, bool, error) {
	if err := revocationhealth.ValidateIntent(intent); err != nil {
		return events.Event{}, false, err
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return events.Event{}, false, err
	}
	var ev events.Event
	inserted := false
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ev, err = o.log.Append(ctx, events.Event{
			ID: intent.ID, Type: projections.EventRevocationProbeQueued,
			TenantID: tenantID, Data: payload,
		})
		if err != nil {
			return err
		}
		if ev.ID != intent.ID || ev.Type != projections.EventRevocationProbeQueued ||
			ev.TenantID != tenantID || !bytes.Equal(ev.Data, payload) {
			return fmt.Errorf("%w: canonical revocation probe differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		inserted, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: revocationhealth.JobKind,
			IdempotencyKey: ev.ID, Payload: ev.Data,
			RequiredAgentRole: intent.RequiredAgentRole,
			RequiredAgentID:   intent.RequiredAgentID,
		})
		return err
	})
	return ev, inserted, err
}

// RecordRevocationHealthObservedWithEventID appends one signed-receipt-bound
// observation, projects it, and enqueues alerts in one tenant transaction.
func (o *Orchestrator) RecordRevocationHealthObservedWithEventID(
	ctx context.Context,
	tenantID, eventID string,
	observed revocationhealth.Observed,
) error {
	if strings.TrimSpace(eventID) == "" {
		return errors.New("orchestrator: revocation observation event id is required")
	}
	// Human text from the relay is not event authority. The closed detail code
	// carries the verdict and keeps retained events free of agent-controlled prose.
	for i := range observed.Findings {
		observed.Findings[i].Detail = ""
	}
	if err := revocationhealth.ValidateObserved(observed); err != nil {
		return err
	}
	payload, err := json.Marshal(observed)
	if err != nil {
		return err
	}
	var ev events.Event
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ev, err = o.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventRevocationHealthObserved,
			TenantID: tenantID, Data: payload,
		})
		if err != nil {
			return err
		}
		if ev.ID != eventID || ev.Type != projections.EventRevocationHealthObserved ||
			ev.TenantID != tenantID || !bytes.Equal(ev.Data, payload) {
			return fmt.Errorf("%w: canonical revocation observation differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		for _, entry := range revocationAlertEntries(ev.TenantID, ev.ID, observed) {
			if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func revocationAlertEntries(tenantID, eventID string, observed revocationhealth.Observed) []Entry {
	byKey := make(map[string]revocationhealth.Target, len(observed.Targets))
	for _, target := range observed.Targets {
		byKey[target.Key] = target
	}
	entries := make([]Entry, 0, len(observed.Findings))
	for _, finding := range observed.Findings {
		if finding.Status == revocationhealth.StatusFresh {
			continue
		}
		target, ok := byKey[finding.TargetKey]
		if !ok {
			continue
		}
		severity := notify.AlertSeverityWarning
		if finding.Status == revocationhealth.StatusStale || finding.Status == revocationhealth.StatusUnparseable {
			severity = notify.AlertSeverityCritical
		}
		payload, _ := json.Marshal(notify.Alert{
			Kind: notify.KindRevocationHealth, TenantID: tenantID,
			CertificateID: target.CertificateID, Subject: target.CertificateSubject,
			Serial: target.CertificateSerial, Detail: finding.DetailCode, Severity: severity,
			EndpointAddress: target.Endpoint, Vantage: revocationhealth.RequiredRoleNetwork,
			Mismatch: string(finding.Status),
		})
		entries = append(entries, Entry{
			TenantID: tenantID, Destination: notify.DestinationRevocation,
			IdempotencyKey: eventID + ":" + target.Key, Payload: payload,
		})
	}
	return entries
}

func (o *Orchestrator) reconcileRevocationProbe(ctx context.Context, ev events.Event) (bool, error) {
	if err := projections.ValidateSchemaVersion(ev); err != nil {
		return false, err
	}
	var intent revocationhealth.Intent
	if err := json.Unmarshal(ev.Data, &intent); err != nil {
		return false, fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
	}
	if err := revocationhealth.ValidateIntent(intent); err != nil {
		return false, err
	}
	var inserted bool
	err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		var err error
		inserted, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: ev.TenantID, Destination: revocationhealth.JobKind,
			IdempotencyKey: ev.ID, Payload: ev.Data,
			RequiredAgentRole: intent.RequiredAgentRole, RequiredAgentID: intent.RequiredAgentID,
		})
		return err
	})
	return inserted, err
}

func (o *Orchestrator) reconcileRevocationAlerts(ctx context.Context, ev events.Event) (int, error) {
	if err := projections.ValidateSchemaVersion(ev); err != nil {
		return 0, err
	}
	var observed revocationhealth.Observed
	if err := json.Unmarshal(ev.Data, &observed); err != nil {
		return 0, fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
	}
	if err := revocationhealth.ValidateObserved(observed); err != nil {
		return 0, fmt.Errorf("orchestrator: reconcile validate %s (seq %d): %w", ev.Type, ev.Sequence, err)
	}
	entries := revocationAlertEntries(ev.TenantID, ev.ID, observed)
	inserted := 0
	err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		for _, entry := range entries {
			created, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry)
			if err != nil {
				return err
			}
			if created {
				inserted++
			}
		}
		return nil
	})
	return inserted, err
}
