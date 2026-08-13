// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/ticketintake"
)

var ErrTicketIntakeSweepInProgress = errors.New("orchestrator: ticket intake schedule has an incomplete sweep")

var ticketIntakeSweepNamespace = uuid.MustParse("fc88ab2a-c740-58f8-bf5d-955011978db8")

const ticketSyncDestination = "ticket.sync"

func (o *Orchestrator) QueueTicketIntakeSweep(
	ctx context.Context,
	tenantID string,
	intent ticketintake.SyncIntent,
	dispatchedAt time.Time,
) error {
	if dispatchedAt.IsZero() || intent.Cursor != "" || intent.ReadCount != 0 {
		return fmt.Errorf("orchestrator: invalid initial ticket intake checkpoint")
	}
	payload, err := json.Marshal(projections.TicketIntakeSweepDispatched{Intent: intent, DispatchedAt: dispatchedAt.UTC()})
	if err != nil {
		return err
	}
	eventID := uuid.NewSHA1(ticketIntakeSweepNamespace,
		[]byte("dispatch\x00"+tenantID+"\x00"+intent.System+"\x00"+intent.SweepID)).String()
	return o.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		return o.emitTicketIntakeEventWithContinuation(lockCtx, events.Event{
			ID: eventID, Type: projections.EventTicketIntakeSweepDispatched, TenantID: tenantID, Data: payload,
		}, &intent)
	})
}

func (o *Orchestrator) ResumeTicketIntakeSweep(ctx context.Context, tenantID string, intent ticketintake.SyncIntent) error {
	if o.outbox == nil {
		return fmt.Errorf("orchestrator: ticket intake outbox is not configured")
	}
	entry, err := ticketIntakeOutboxEntry(tenantID, intent)
	if err != nil {
		return err
	}
	return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.store.ValidateTicketIntakeIntentTx(ctx, tx, tenantID, intent); err != nil {
			return err
		}
		_, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry)
		return err
	})
}

func (o *Orchestrator) RecordTicketIntakeSweepPage(
	ctx context.Context,
	tenantID, resultKey string,
	page projections.TicketIntakeSweepPageObserved,
) error {
	if err := validateTicketIntakePageEvent(tenantID, resultKey, page); err != nil {
		return err
	}
	payload, err := json.Marshal(page)
	if err != nil {
		return err
	}
	eventID := uuid.NewSHA1(ticketIntakeSweepNamespace,
		[]byte("page\x00"+tenantID+"\x00"+resultKey)).String()
	return o.emitTicketIntakeEventWithContinuation(ctx, events.Event{
		ID: eventID, Type: projections.EventTicketIntakeSweepPageObserved, TenantID: tenantID, Data: payload,
	}, page.NextIntent)
}

func (o *Orchestrator) RecordTicketIntakeSweepFailure(
	ctx context.Context,
	tenantID, resultKey string,
	attempt int,
	intent ticketintake.SyncIntent,
	failedAt time.Time,
	detail string,
) error {
	detail = strings.TrimSpace(detail)
	if resultKey == "" || attempt <= 0 || failedAt.IsZero() || detail == "" {
		return fmt.Errorf("orchestrator: invalid ticket intake failure receipt")
	}
	if _, err := ticketIntakeOutboxEntry(tenantID, intent); err != nil {
		return err
	}
	payload, err := json.Marshal(projections.TicketIntakeSweepFailed{
		System: intent.System, SweepID: intent.SweepID, Cursor: intent.Cursor,
		FailedAt: failedAt.UTC(), Detail: detail,
	})
	if err != nil {
		return err
	}
	eventID := uuid.NewSHA1(ticketIntakeSweepNamespace,
		[]byte(fmt.Sprintf("failure\x00%s\x00%s\x00%d", tenantID, resultKey, attempt))).String()
	event, err := o.emitPrepared(ctx, events.Event{
		ID: eventID, Type: projections.EventTicketIntakeSweepFailed, TenantID: tenantID, Data: payload,
	})
	if err != nil {
		return err
	}
	if event.ID != eventID || event.Type != projections.EventTicketIntakeSweepFailed ||
		event.TenantID != tenantID || !bytes.Equal(event.Data, payload) {
		return fmt.Errorf("%w: canonical ticket intake failure event differs", store.ErrIdempotencyConflict)
	}
	return nil
}

func (o *Orchestrator) emitTicketIntakeEventWithContinuation(
	ctx context.Context,
	next events.Event,
	continuation *ticketintake.SyncIntent,
) error {
	if o.outbox == nil {
		return fmt.Errorf("orchestrator: ticket intake outbox is not configured")
	}
	var continuationEntry *Entry
	if continuation != nil {
		entry, err := ticketIntakeOutboxEntry(next.TenantID, *continuation)
		if err != nil {
			return err
		}
		continuationEntry = &entry
	}
	return o.store.WithTenant(ctx, next.TenantID, func(tx pgx.Tx) error {
		event, err := o.log.Append(ctx, next)
		if err != nil {
			return err
		}
		if event.ID != next.ID || event.Type != next.Type || event.TenantID != next.TenantID ||
			!bytes.Equal(event.Data, next.Data) {
			return fmt.Errorf("%w: canonical ticket intake event differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		if continuationEntry == nil {
			return nil
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, *continuationEntry)
		return err
	})
}

func ticketIntakeOutboxEntry(tenantID string, intent ticketintake.SyncIntent) (Entry, error) {
	parsed, err := uuid.Parse(intent.SweepID)
	if err != nil || parsed == uuid.Nil || intent.PageLimit <= 0 || intent.PageLimit > ticketintake.MaxTickets ||
		intent.ReadCount < 0 || (intent.ExpectedCount != nil && *intent.ExpectedCount < intent.ReadCount) ||
		!strings.HasPrefix(strings.TrimSpace(intent.TokenRef), "secret://") {
		return Entry{}, fmt.Errorf("orchestrator: invalid ticket intake intent")
	}
	if _, err := ticketintake.Endpoint(intent); err != nil {
		return Entry{}, err
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return Entry{}, err
	}
	cursor := intent.Cursor
	if cursor == "" {
		cursor = "start"
	}
	return Entry{
		TenantID: tenantID, Destination: ticketSyncDestination,
		IdempotencyKey: "ticket-sync:" + tenantID + ":" + intent.System + ":" + intent.SweepID + ":" + cursor,
		Payload:        payload, RequiredAgentRole: "network",
	}, nil
}

func validateTicketIntakePageEvent(tenantID, resultKey string, page projections.TicketIntakeSweepPageObserved) error {
	if strings.TrimSpace(resultKey) == "" || page.ObservedAt.IsZero() || page.Eligible < 0 || page.Skipped < 0 {
		return fmt.Errorf("orchestrator: invalid ticket intake page event")
	}
	if _, err := ticketIntakeOutboxEntry(tenantID, page.Intent); err != nil {
		return err
	}
	pageSize := len(page.SourceRefs)
	if pageSize > page.Intent.PageLimit || page.ReadCount != page.Intent.ReadCount+pageSize ||
		page.Eligible+page.Skipped != pageSize ||
		(page.ExpectedCount != nil && *page.ExpectedCount < page.ReadCount) ||
		(page.Complete && page.ExpectedCount != nil && *page.ExpectedCount != page.ReadCount) ||
		(page.Complete && page.NextCursor != "") || (!page.Complete && page.NextCursor == "") {
		return fmt.Errorf("orchestrator: invalid bounded ticket intake page progress")
	}
	if page.Intent.System == ticketintake.SystemServiceNow && !page.Complete &&
		(pageSize != page.Intent.PageLimit || page.NextCursor != page.SourceRefs[len(page.SourceRefs)-1]) {
		return fmt.Errorf("orchestrator: invalid ServiceNow ticket continuation")
	}
	seen := map[string]bool{}
	var previous string
	var previousJira uint64
	for _, ref := range page.SourceRefs {
		if !ticketintake.ValidSourceRef(ref) || seen[ref] {
			return fmt.Errorf("orchestrator: invalid ticket source reference")
		}
		if page.Intent.System == ticketintake.SystemServiceNow {
			if (previous == "" && page.Intent.Cursor != "" && ref <= page.Intent.Cursor) || (previous != "" && ref <= previous) {
				return fmt.Errorf("orchestrator: ServiceNow source references are not a strict keyset continuation")
			}
			previous = ref
		} else {
			id, err := strconv.ParseUint(ref, 10, 64)
			if err != nil || id == 0 || (previousJira != 0 && id <= previousJira) {
				return fmt.Errorf("orchestrator: Jira source references are not strictly ordered")
			}
			previousJira = id
		}
		seen[ref] = true
	}
	if page.Complete {
		if page.NextIntent != nil {
			return fmt.Errorf("orchestrator: terminal ticket page carries a continuation")
		}
		return nil
	}
	if page.NextIntent == nil || page.NextIntent.System != page.Intent.System ||
		page.NextIntent.InstanceURL != page.Intent.InstanceURL || page.NextIntent.TokenRef != page.Intent.TokenRef ||
		page.NextIntent.SNTable != page.Intent.SNTable || page.NextIntent.JiraProject != page.Intent.JiraProject ||
		page.NextIntent.Query != page.Intent.Query || page.NextIntent.SubjectField != page.Intent.SubjectField ||
		page.NextIntent.ProfileField != page.Intent.ProfileField || page.NextIntent.RequesterField != page.Intent.RequesterField ||
		page.NextIntent.JustificationField != page.Intent.JustificationField ||
		page.NextIntent.PageLimit != page.Intent.PageLimit || page.NextIntent.SweepID != page.Intent.SweepID ||
		page.NextIntent.Cursor != page.NextCursor || page.NextIntent.ReadCount != page.ReadCount ||
		!sameCMDBExpectedCount(page.NextIntent.ExpectedCount, page.ExpectedCount) {
		return fmt.Errorf("orchestrator: ticket page continuation differs from its committed boundary")
	}
	return nil
}
