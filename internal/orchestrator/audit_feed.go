// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	DestinationAuditFeedSplunk   = "audit.feed.splunk"
	DestinationAuditFeedSentinel = "audit.feed.sentinel"
)

func AuditFeedDestination(provider string) (string, bool) {
	switch provider {
	case auditsink.ProviderSplunkHEC:
		return DestinationAuditFeedSplunk, true
	case auditsink.ProviderSentinel:
		return DestinationAuditFeedSentinel, true
	default:
		return "", false
	}
}

func (o *Orchestrator) ConfigureAuditFeed(ctx context.Context, tenantID string, in projections.AuditFeedDestinationConfigured) (store.AuditFeed, error) {
	payload, err := json.Marshal(in)
	if err != nil {
		return store.AuditFeed{}, err
	}
	ev, err := o.emit(ctx, projections.EventAuditFeedDestinationConfigured, tenantID, payload)
	if err != nil {
		return store.AuditFeed{}, err
	}
	feed, found, err := o.store.GetAuditFeed(ctx, tenantID, in.ID)
	if err != nil {
		return store.AuditFeed{}, err
	}
	if !found || feed.ConfigEventSequence != ev.Sequence {
		return store.AuditFeed{}, fmt.Errorf("orchestrator: configured audit feed did not project exact event authority")
	}
	return feed, nil
}

func (o *Orchestrator) RecordAuditFeedScheduleChecked(ctx context.Context, tenantID string, feed store.AuditFeed) error {
	pl := projections.AuditFeedScheduleChecked{
		DestinationID: feed.ID, ConfigEventSequence: feed.ConfigEventSequence,
		Cursor: feed.LastDeliveredSequence, IntervalSeconds: feed.IntervalSeconds,
		ScheduledFor: feed.NextRunAt.UTC().Format(time.RFC3339Nano),
	}
	payload, err := json.Marshal(pl)
	if err != nil {
		return err
	}
	stableID := "audit-feed-checked:" + feed.ID + ":" + strconv.FormatUint(feed.ConfigEventSequence, 10) + ":" +
		strconv.FormatInt(feed.NextRunAt.UTC().UnixNano(), 10)
	_, err = o.emitPrepared(ctx, events.Event{
		ID: stableID, Type: projections.EventAuditFeedScheduleChecked,
		TenantID: tenantID, Data: payload,
	})
	return err
}

// QueueAuditFeedBatch records the exact immutable range and its outbox command
// in one tenant transaction. The outbox payload contains the already selected,
// privacy-redacted records, so a retry after restart cannot drift to a newer
// audit generation.
func (o *Orchestrator) QueueAuditFeedBatch(
	ctx context.Context,
	tenantID string,
	feed store.AuditFeed,
	records []auditchain.Record,
	prevHash, chainHead string,
) (projections.AuditFeedBatchQueued, error) {
	if o.outbox == nil || len(records) == 0 || feed.ID == "" || feed.TenantID != tenantID {
		return projections.AuditFeedBatchQueued{}, fmt.Errorf("orchestrator: audit feed batch is incomplete")
	}
	_, ok := AuditFeedDestination(feed.Provider)
	if !ok {
		return projections.AuditFeedBatchQueued{}, fmt.Errorf("orchestrator: unsupported audit feed provider %q", feed.Provider)
	}
	start, end := records[0].Sequence, records[len(records)-1].Sequence
	if start == 0 || end < start || chainHead == "" {
		return projections.AuditFeedBatchQueued{}, fmt.Errorf("orchestrator: audit feed batch range is invalid")
	}
	recordIDs := make([]string, len(records))
	for i, record := range records {
		if record.TenantID != tenantID || record.ID == "" || record.Sequence < start || record.Sequence > end {
			return projections.AuditFeedBatchQueued{}, fmt.Errorf("orchestrator: audit feed record escaped exact tenant/range authority")
		}
		if i > 0 && record.Sequence <= records[i-1].Sequence {
			return projections.AuditFeedBatchQueued{}, fmt.Errorf("orchestrator: audit feed records are not in strict sequence order")
		}
		recordIDs[i] = record.ID
	}
	name := tenantID + ":" + feed.ID + ":" + strconv.FormatUint(start, 10) + ":" + strconv.FormatUint(end, 10)
	batchID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String()
	outboxKey := "audit-feed:" + batchID
	queued := projections.AuditFeedBatchQueued{
		BatchID: batchID, DestinationID: feed.ID, Provider: feed.Provider,
		EndpointURL: feed.EndpointURL, TokenRef: feed.TokenRef,
		AllowPrivateEndpoint: feed.AllowPrivateEndpoint,
		PrivateEgressCIDRs:   append([]string(nil), feed.PrivateEgressCIDRs...),
		IntervalSeconds:      feed.IntervalSeconds, StartSequence: start, EndSequence: end,
		RecordCount: len(records), RecordIDs: recordIDs, PrevHash: prevHash,
		ChainHead: chainHead, OutboxIdempotencyKey: outboxKey,
	}
	eventPayload, err := json.Marshal(queued)
	if err != nil {
		return projections.AuditFeedBatchQueued{}, err
	}
	entry, err := auditFeedOutboxEntry(tenantID, queued, records)
	if err != nil {
		return projections.AuditFeedBatchQueued{}, err
	}
	next := events.Event{
		ID: "audit-feed-batch:" + batchID, Type: projections.EventAuditFeedBatchQueued,
		TenantID: tenantID, Data: eventPayload,
	}
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ev, err := o.log.Append(ctx, next)
		if err != nil {
			return err
		}
		if ev.ID != next.ID || ev.Type != next.Type || ev.TenantID != next.TenantID || !bytes.Equal(ev.Data, next.Data) {
			return fmt.Errorf("%w: canonical audit feed batch differs", store.ErrAuditFeedBatchConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, entry)
		return err
	})
	return queued, err
}

func auditFeedOutboxEntry(tenantID string, queued projections.AuditFeedBatchQueued, records []auditchain.Record) (Entry, error) {
	destination, ok := AuditFeedDestination(queued.Provider)
	if !ok || tenantID == "" || queued.BatchID == "" || queued.DestinationID == "" ||
		queued.OutboxIdempotencyKey == "" || len(records) == 0 ||
		len(queued.RecordIDs) != len(records) {
		return Entry{}, fmt.Errorf("orchestrator: audit feed outbox authority is incomplete")
	}
	for i, record := range records {
		if record.TenantID != tenantID || record.ID != queued.RecordIDs[i] {
			return Entry{}, fmt.Errorf("orchestrator: audit feed outbox record identity changed")
		}
	}
	payload, err := json.Marshal(auditsink.FeedBatch{
		BatchID: queued.BatchID, DestinationID: queued.DestinationID, Provider: queued.Provider,
		EndpointURL: queued.EndpointURL, TokenRef: queued.TokenRef,
		AllowPrivateEndpoint: queued.AllowPrivateEndpoint,
		PrivateEgressCIDRs:   append([]string(nil), queued.PrivateEgressCIDRs...),
		StartSequence:        queued.StartSequence, EndSequence: queued.EndSequence,
		PrevHash: queued.PrevHash, ChainHead: queued.ChainHead,
		Records: append([]auditchain.Record(nil), records...),
	})
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		TenantID: tenantID, Destination: destination,
		IdempotencyKey: queued.OutboxIdempotencyKey,
		EffectLane:     destination + ":" + queued.DestinationID, Payload: payload,
	}, nil
}

func (o *Orchestrator) RecordAuditFeedDelivered(ctx context.Context, tenantID string, batch auditsink.FeedBatch, outboxKey, collectorRequestID string) error {
	pl := projections.AuditFeedBatchDelivered{
		BatchID: batch.BatchID, DestinationID: batch.DestinationID, Provider: batch.Provider,
		StartSequence: batch.StartSequence, EndSequence: batch.EndSequence,
		RecordCount: len(batch.Records), ChainHead: batch.ChainHead,
		OutboxIdempotencyKey: outboxKey, CollectorRequestID: strings.TrimSpace(collectorRequestID),
	}
	payload, err := json.Marshal(pl)
	if err != nil {
		return err
	}
	_, err = o.emitPrepared(ctx, events.Event{
		ID: "audit-feed-delivered:" + batch.BatchID, Type: projections.EventAuditFeedBatchDelivered,
		TenantID: tenantID, Data: payload,
	})
	return err
}

func (o *Orchestrator) RecordAuditFeedFailed(ctx context.Context, tenantID string, batch auditsink.FeedBatch, outboxKey, errorCode string) error {
	errorCode = strings.TrimSpace(errorCode)
	if errorCode == "" {
		errorCode = "retry_exhausted"
	}
	payload, err := json.Marshal(projections.AuditFeedBatchFailed{
		BatchID: batch.BatchID, DestinationID: batch.DestinationID,
		OutboxIdempotencyKey: outboxKey, ErrorCode: errorCode,
	})
	if err != nil {
		return err
	}
	_, err = o.emitPrepared(ctx, events.Event{
		ID: "audit-feed-failed:" + batch.BatchID, Type: projections.EventAuditFeedBatchFailed,
		TenantID: tenantID, Data: payload,
	})
	return err
}
