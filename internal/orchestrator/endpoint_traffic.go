// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// endpointTrafficNamespace keys a replaced endpoint's wire-evidence events by
// tenant, endpoint, vantage, certificate and replacement, so a pass that runs
// again appends nothing new, and the same certificate deployed again later is
// a new wait.
var endpointTrafficNamespace = uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl/endpoint-traffic"))

// RecordEndpointTrafficObserved records the wire evidence for a replaced
// endpoint still serving fingerprint (X3-L1): the observer finding that saw
// new connections at it after the replacement, and when.
func (o *Orchestrator) RecordEndpointTrafficObserved(ctx context.Context, tenantID, endpointID, vantage, fingerprint, findingID string, replacedAt, at time.Time) error {
	data, err := json.Marshal(projections.EndpointTrafficObserved{
		EndpointID: endpointID, Vantage: vantage, Fingerprint: fingerprint, FindingID: findingID, ObservedAt: at.UTC(),
	})
	if err != nil {
		return err
	}
	return o.emitEndpointTraffic(ctx, tenantID, projections.EventEndpointTrafficObserved, endpointID, vantage, fingerprint, replacedAt, data)
}

// RecordEndpointTrafficUnobserved records that a replaced endpoint's window
// passed without wire evidence for fingerprint.
func (o *Orchestrator) RecordEndpointTrafficUnobserved(ctx context.Context, tenantID, endpointID, vantage, fingerprint string, replacedAt, since time.Time) error {
	data, err := json.Marshal(projections.EndpointTrafficUnobserved{
		EndpointID: endpointID, Vantage: vantage, Fingerprint: fingerprint, Since: since.UTC(),
	})
	if err != nil {
		return err
	}
	return o.emitEndpointTraffic(ctx, tenantID, projections.EventEndpointTrafficUnobserved, endpointID, vantage, fingerprint, replacedAt, data)
}

func (o *Orchestrator) emitEndpointTraffic(ctx context.Context, tenantID, eventType, endpointID, vantage, fingerprint string, replacedAt time.Time, data []byte) error {
	id := uuid.NewSHA1(endpointTrafficNamespace, []byte(tenantID+"\x00"+eventType+"\x00"+endpointID+"\x00"+vantage+"\x00"+fingerprint+
		"\x00"+replacedAt.UTC().Format(time.RFC3339Nano))).String()
	next := events.Event{ID: id, Type: eventType, TenantID: tenantID, SchemaVersion: 1, Data: data}
	if actor, ok := events.ActorFromContext(ctx); ok {
		next.Actor = &actor
	}
	_, err := o.emitPrepared(ctx, next)
	return err
}
