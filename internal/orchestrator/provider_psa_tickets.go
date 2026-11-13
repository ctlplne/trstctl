// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// DestinationPSATicket is the outbox destination of one PSA ticket operation
// (MSP-3): open, add a note, or close a customer's ticket in a PSA target.
const DestinationPSATicket = "provider.psa_ticket"

// PSATicketAlert is one alert a PSA target should see as a ticket.
type PSATicketAlert struct {
	TargetID          string
	AlertKey          string
	Kind              string
	ExternalCompanyID string
	Summary           string
	Note              string
	AlertRef          string
}

// PSATicketOpKey is the outbox key of one ticket operation: one open and one
// close per generation, one note per alert.
func PSATicketOpKey(targetID, alertKey string, generation int, op, alertRef string) string {
	key := "psa-ticket:" + targetID + ":" + crypto.SHA256Hex([]byte(alertKey))[:24] + ":" + strconv.Itoa(generation) + ":" + op
	if op == store.PSATicketOpUpdate {
		key += ":" + crypto.SHA256Hex([]byte(alertRef))[:24]
	}
	return key
}

// PSATicketAlertEventID is the event that records one alert for one target:
// a retried notification finds it and does nothing.
func PSATicketAlertEventID(tenantID, targetID, alertKey, alertRef string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("psa-ticket-alert\x00"+tenantID+"\x00"+targetID+"\x00"+alertKey+"\x00"+alertRef)).String()
}

func lockPSATicketTx(ctx context.Context, tx pgx.Tx, tenantID, targetID, alertKey string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"psa-ticket|"+tenantID+"|"+targetID+"|"+alertKey)
	return err
}

// QueuePSATicketAlert records an alert against its subject's ticket and
// queues the PSA operation in the same tenant transaction: the subject's
// first alert (or the first after its ticket closed or failed, or after the
// customer moved to another company) opens a ticket of the next generation;
// a later alert while it is open adds a note. The same alert twice is a
// no-op. It reports the operation queued ("" for none).
func (o *Orchestrator) QueuePSATicketAlert(ctx context.Context, tenantID string, a PSATicketAlert) (string, error) {
	if o.outbox == nil {
		return "", errors.New("orchestrator: PSA ticket outbox is unavailable")
	}
	if strings.TrimSpace(a.AlertRef) == "" {
		return "", errors.New("orchestrator: a PSA ticket alert names the alert it came from")
	}
	eventID := PSATicketAlertEventID(tenantID, a.TargetID, a.AlertKey, a.AlertRef)
	if _, found, err := o.log.EventByID(ctx, eventID); err != nil || found {
		return "", err
	}
	queued := ""
	err := o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := lockPSATicketTx(ctx, tx, tenantID, a.TargetID, a.AlertKey); err != nil {
			return err
		}
		cur, found, err := store.PSATicketForTx(ctx, tx, tenantID, a.TargetID, a.AlertKey)
		if err != nil {
			return err
		}
		ev := projections.PSATicketEvent{TargetID: a.TargetID, AlertKey: a.AlertKey, Kind: a.Kind,
			ExternalCompanyID: a.ExternalCompanyID, Summary: truncateText(a.Summary, projections.PSATicketSummaryMax),
			Note: truncateText(a.Note, projections.PSATicketNoteMax), AlertRef: a.AlertRef}
		switch {
		case !found:
			ev.Op, ev.Generation = store.PSATicketOpOpen, 1
		case cur.Status == store.PSATicketClosed || cur.Status == store.PSATicketFailed || cur.ExternalCompanyID != a.ExternalCompanyID:
			ev.Op, ev.Generation = store.PSATicketOpOpen, cur.Generation+1
		case cur.LastAlertRef == a.AlertRef:
			return nil
		default:
			ev.Op, ev.Generation, ev.ExternalCompanyID = store.PSATicketOpUpdate, cur.Generation, cur.ExternalCompanyID
		}
		if err := projections.ValidatePSATicketEvent(projections.EventPSATicketRequested, ev); err != nil {
			return fmt.Errorf("orchestrator: %w", err)
		}
		payload, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		appended, err := o.log.Append(ctx, events.Event{ID: eventID, Type: projections.EventPSATicketRequested, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, appended); err != nil {
			return err
		}
		if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: DestinationPSATicket,
			IdempotencyKey: PSATicketOpKey(ev.TargetID, ev.AlertKey, ev.Generation, ev.Op, ev.AlertRef), Payload: appended.Data}); err != nil {
			return err
		}
		queued = ev.Op
		return nil
	})
	return queued, err
}

// QueuePSATicketClose queues the close of an open ticket whose condition
// cleared, with the reason; any other state is left alone.
func (o *Orchestrator) QueuePSATicketClose(ctx context.Context, tenantID, targetID, alertKey string, generation int, reason string) (bool, error) {
	if o.outbox == nil {
		return false, errors.New("orchestrator: PSA ticket outbox is unavailable")
	}
	queued := false
	err := o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := lockPSATicketTx(ctx, tx, tenantID, targetID, alertKey); err != nil {
			return err
		}
		cur, found, err := store.PSATicketForTx(ctx, tx, tenantID, targetID, alertKey)
		if err != nil || !found || cur.Generation != generation || cur.Status != store.PSATicketOpen {
			return err
		}
		ev := projections.PSATicketEvent{TargetID: targetID, AlertKey: alertKey, Generation: generation, Op: store.PSATicketOpClose,
			Kind: cur.Kind, ExternalCompanyID: cur.ExternalCompanyID, Reason: truncateText(reason, 2000)}
		if err := projections.ValidatePSATicketEvent(projections.EventPSATicketRequested, ev); err != nil {
			return fmt.Errorf("orchestrator: %w", err)
		}
		payload, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		appended, err := o.log.Append(ctx, events.Event{Type: projections.EventPSATicketRequested, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, appended); err != nil {
			return err
		}
		queued, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: DestinationPSATicket,
			IdempotencyKey: PSATicketOpKey(targetID, alertKey, generation, store.PSATicketOpClose, ""), Payload: appended.Data})
		return err
	})
	return queued, err
}

// RecordPSATicketOutcome records an operation's outcome: the PSA's ticket ID
// when it opened, or why it failed (with one alert). An outcome for an
// operation no longer in flight is ignored.
func (o *Orchestrator) RecordPSATicketOutcome(ctx context.Context, tenantID string, outcome projections.PSATicketEvent) error {
	outcome.Note, outcome.Summary = "", ""
	if err := projections.ValidatePSATicketEvent(projections.EventPSATicketRecorded, outcome); err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	payload, err := json.Marshal(outcome)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := lockPSATicketTx(ctx, tx, tenantID, outcome.TargetID, outcome.AlertKey); err != nil {
			return err
		}
		cur, found, err := store.PSATicketForTx(ctx, tx, tenantID, outcome.TargetID, outcome.AlertKey)
		if err != nil || !found || cur.Generation != outcome.Generation || !psaTicketOpInFlight(cur.Status, outcome.Op) {
			return err
		}
		ev, err := o.log.Append(ctx, events.Event{Type: projections.EventPSATicketRecorded, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		if !outcome.OK {
			_, err = o.enqueuePSATicketAlertTx(ctx, tx, tenantID, ev.ID, outcome)
		}
		return err
	})
}

func psaTicketOpInFlight(status, op string) bool {
	switch op {
	case store.PSATicketOpOpen:
		return status == store.PSATicketOpening
	case store.PSATicketOpClose:
		return status == store.PSATicketClosing
	default:
		return status == store.PSATicketOpening || status == store.PSATicketOpen
	}
}

func (o *Orchestrator) enqueuePSATicketAlertTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string, outcome projections.PSATicketEvent) (bool, error) {
	key := notify.KindPSATicketFailed + ":" + eventID
	payload, err := json.Marshal(notify.Alert{
		Kind: notify.KindPSATicketFailed, TenantID: tenantID, OperationID: key, Severity: notify.AlertSeverityWarning,
		Subject: "PSA target " + outcome.TargetID,
		Detail:  "The PSA ticket operation " + outcome.Op + " for " + outcome.AlertKey + " failed: " + strings.TrimSpace(outcome.Reason),
	})
	if err != nil {
		return false, err
	}
	return o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: notify.DestinationBillingSync, IdempotencyKey: key, Payload: payload})
}

// reconcilePSATicket re-enqueues an operation still in flight, or a failed
// operation's alert, whose transaction appended the event but did not commit
// the outbox entry.
func (o *Orchestrator) reconcilePSATicket(ctx context.Context, ev events.Event) (bool, error) {
	var t projections.PSATicketEvent
	if err := json.Unmarshal(ev.Data, &t); err != nil {
		return false, fmt.Errorf("decode retained PSA ticket event: %w", err)
	}
	if err := projections.ValidatePSATicketEvent(ev.Type, t); err != nil {
		return false, err
	}
	inserted := false
	err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		cur, found, err := store.PSATicketForTx(ctx, tx, ev.TenantID, t.TargetID, t.AlertKey)
		if err != nil || !found || cur.Generation != t.Generation {
			return err
		}
		if ev.Type == projections.EventPSATicketRecorded {
			if !t.OK {
				inserted, err = o.enqueuePSATicketAlertTx(ctx, tx, ev.TenantID, ev.ID, t)
			}
			return err
		}
		inFlight := (t.Op == store.PSATicketOpOpen && cur.Status == store.PSATicketOpening) ||
			(t.Op == store.PSATicketOpClose && cur.Status == store.PSATicketClosing) ||
			(t.Op == store.PSATicketOpUpdate && cur.LastAlertRef == t.AlertRef && (cur.Status == store.PSATicketOpening || cur.Status == store.PSATicketOpen))
		if !inFlight {
			return nil
		}
		inserted, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: ev.TenantID, Destination: DestinationPSATicket,
			IdempotencyKey: PSATicketOpKey(t.TargetID, t.AlertKey, t.Generation, t.Op, t.AlertRef), Payload: ev.Data})
		return err
	})
	return inserted, err
}

// truncateText bounds s to max bytes on a rune boundary.
func truncateText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }
