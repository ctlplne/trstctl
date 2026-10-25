// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// An operator's request to probe the tenant's CRL and OCSP endpoints now
// rather than at the next hourly sweep. Without it, an operator who fixed a
// relay's trust bundle or a distribution point kept reading the stale failure
// for up to an hour, and a control-plane restart's sweep deduplicated inside
// the hour as well.
const (
	// DestinationRevocationProbeRequest is handled by the server, which derives
	// the targets exactly as the hourly sweep does and queues relay probes under
	// the request's own bucket.
	DestinationRevocationProbeRequest = "revocation.probe.request"
	// EventRevocationProbeRequested records who asked for the probe, and when.
	EventRevocationProbeRequested = "revocation.probe.requested"
	// RevocationProbeRequestBucketPrefix starts every on-demand probe bucket.
	RevocationProbeRequestBucketPrefix = "manual:"
)

var revocationProbeRequestNamespace = uuid.MustParse("4f2a9d3e-6c1b-4f5e-9a7d-2b8c0e1f3a64")

// RevocationProbeRequest is the recorded request and the outbox payload.
type RevocationProbeRequest struct {
	Bucket      string `json:"bucket"`
	RequestedBy string `json:"requested_by"`
}

// RequestRevocationProbe records an operator's request to probe the tenant's
// revocation endpoints now and queues it, at most once per tenant and minute:
// a second request inside the same minute converges on the first and reports
// queued=false, so repeated clicks never multiply relay work.
func (o *Orchestrator) RequestRevocationProbe(ctx context.Context, tenantID, requestedBy string) (RevocationProbeRequest, bool, error) {
	requestedBy = strings.TrimSpace(requestedBy)
	if tenantID == "" || requestedBy == "" {
		return RevocationProbeRequest{}, false, errors.New("orchestrator: a revocation probe request needs a tenant and the operator who made it")
	}
	now, err := o.store.DatabaseTime(ctx)
	if err != nil {
		return RevocationProbeRequest{}, false, err
	}
	request := RevocationProbeRequest{
		Bucket:      RevocationProbeRequestBucketPrefix + now.UTC().Truncate(time.Minute).Format(time.RFC3339),
		RequestedBy: requestedBy,
	}
	eventID := uuid.NewSHA1(revocationProbeRequestNamespace, []byte(tenantID+"\x00"+request.Bucket)).String()
	payload, err := json.Marshal(request)
	if err != nil {
		return RevocationProbeRequest{}, false, err
	}
	queued := false
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if existing, found, err := o.log.EventByID(ctx, eventID); err != nil {
			return err
		} else if found {
			// Another operator, or a retry, asked in the same minute.
			var recorded RevocationProbeRequest
			if existing.Type != EventRevocationProbeRequested || existing.TenantID != tenantID ||
				json.Unmarshal(existing.Data, &recorded) != nil || recorded.Bucket != request.Bucket {
				return fmt.Errorf("%w: event %s is not this tenant's probe request", store.ErrIdempotencyConflict, eventID)
			}
			request = recorded
			return nil
		}
		ev, err := o.log.Append(ctx, events.Event{ID: eventID, Type: EventRevocationProbeRequested, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if ev.ID != eventID || ev.Type != EventRevocationProbeRequested || ev.TenantID != tenantID || !bytes.Equal(ev.Data, payload) {
			return fmt.Errorf("%w: canonical revocation probe request differs", store.ErrIdempotencyConflict)
		}
		queued, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: DestinationRevocationProbeRequest,
			IdempotencyKey: eventID, Payload: payload,
		})
		return err
	})
	return request, queued, err
}
