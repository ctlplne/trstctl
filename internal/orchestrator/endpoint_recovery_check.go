// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var endpointRecoveryCheckNamespace = uuid.MustParse("e37b4808-4eae-46de-be87-12cc1042d5e8")

// EndpointRecoveryCheckRequest asks a contained target's enrolled host whether
// its profile pins an action that brings the listener back (A210). It names
// only public identifiers; the host's own profile decides what it reports.
type EndpointRecoveryCheckRequest struct {
	TargetID            string
	TargetRevision      string
	RequiredAgentID     string
	RevokedFingerprints []string
	RequestedBy         string
	IdempotencyKey      string
}

// EndpointContainmentReceiptID is the receipt id a containment command of this
// target and request key carries, so a reader can tell which target a receipt
// stopped without the outbox row.
func EndpointContainmentReceiptID(tenantID, targetID, key string) string {
	return endpointContainmentReceiptID(tenantID, targetID, key)
}

// RequestEndpointRecoveryCheck appends the request, projects it and queues the
// read-only job for the exact host agent in one tenant transaction. A retry
// with the same key returns the same check.
func (o *Orchestrator) RequestEndpointRecoveryCheck(ctx context.Context, tenantID string,
	in EndpointRecoveryCheckRequest) (projections.EndpointRecoveryCheckRequested, error) {
	if o == nil || o.log == nil || o.store == nil || o.outbox == nil {
		return projections.EndpointRecoveryCheckRequested{}, errors.New("orchestrator: recovery checks are not configured")
	}
	key := strings.TrimSpace(in.IdempotencyKey)
	seed := []byte(tenantID + "\x00" + strings.TrimSpace(in.TargetID) + "\x00" + key)
	requested := projections.EndpointRecoveryCheckRequested{
		CheckID:        uuid.NewSHA1(endpointRecoveryCheckNamespace, append([]byte("check\x00"), seed...)).String(),
		TargetID:       strings.TrimSpace(in.TargetID),
		TargetRevision: strings.TrimSpace(in.TargetRevision),
		AgentID:        strings.TrimSpace(in.RequiredAgentID),
		RequestedBy:    strings.TrimSpace(in.RequestedBy),
		IdempotencyKey: key,
	}
	for _, fp := range in.RevokedFingerprints {
		requested.RevokedFingerprints = append(requested.RevokedFingerprints, strings.ToLower(strings.TrimSpace(fp)))
	}
	if requested.RequestedBy == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			requested.RequestedBy = actor.Subject
		}
	}
	if err := projections.ValidateEndpointRecoveryCheckRequested(requested); err != nil {
		return projections.EndpointRecoveryCheckRequested{}, fmt.Errorf("orchestrator: %w", err)
	}
	raw, err := json.Marshal(requested)
	if err != nil {
		return projections.EndpointRecoveryCheckRequested{}, err
	}
	intent, err := json.Marshal(relay.RecoveryCheckIntent{
		CheckID: requested.CheckID, TargetID: requested.TargetID, TargetRevision: requested.TargetRevision,
		RequiredAgentID: requested.AgentID, RevokedFingerprints: requested.RevokedFingerprints,
	})
	if err != nil {
		return projections.EndpointRecoveryCheckRequested{}, err
	}
	eventID := uuid.NewSHA1(endpointRecoveryCheckNamespace, append([]byte("event\x00"), seed...)).String()
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var revision string
		var config []byte
		if err := tx.QueryRow(ctx,
			`SELECT revision_id, config FROM deployment_targets WHERE tenant_id = $1 AND id = $2 FOR SHARE`,
			tenantID, requested.TargetID).Scan(&revision, &config); err != nil {
			return err
		}
		if revision != requested.TargetRevision {
			return errors.New("orchestrator: target changed after review; check again")
		}
		if assigned, err := connector.TargetHostAgentID(json.RawMessage(config)); err != nil || assigned != requested.AgentID {
			return errors.New("orchestrator: target no longer names this enrolled host agent")
		}
		event, err := o.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventEndpointRecoveryCheckRequested, TenantID: tenantID, Data: raw,
		})
		if err != nil {
			return err
		}
		if event.ID != eventID || event.Type != projections.EventEndpointRecoveryCheckRequested ||
			event.TenantID != tenantID || !bytes.Equal(event.Data, raw) {
			return fmt.Errorf("%w: recovery check request differs from the retained one", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: relay.KindEndpointRecoveryCheck,
			IdempotencyKey: "endpoint-recovery-check:" + requested.CheckID, Payload: intent,
			EffectLane:        ConnectorTargetEffectLane(requested.TargetID),
			RequiredAgentRole: "host", RequiredAgentID: requested.AgentID,
		})
		return err
	})
	if err != nil {
		return projections.EndpointRecoveryCheckRequested{}, fmt.Errorf("orchestrator: queue recovery check: %w", err)
	}
	return requested, nil
}

// RecordEndpointRecoveryCheck projects a host's signed answer under the
// claim's event id, so a retried report cannot change it.
func (o *Orchestrator) RecordEndpointRecoveryCheck(ctx context.Context, tenantID, eventID string,
	answer projections.EndpointRecoveryChecked) error {
	if err := projections.ValidateEndpointRecoveryChecked(answer); err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	return o.recordEndpointRecoveryAnswer(ctx, tenantID, eventID, projections.EventEndpointRecoveryChecked, answer)
}

// RecordEndpointRecoveryCheckFailure projects a host's signed refusal.
func (o *Orchestrator) RecordEndpointRecoveryCheckFailure(ctx context.Context, tenantID, eventID string,
	failure projections.EndpointRecoveryCheckFailed) error {
	return o.recordEndpointRecoveryAnswer(ctx, tenantID, eventID, projections.EventEndpointRecoveryCheckFailed, failure)
}

func (o *Orchestrator) recordEndpointRecoveryAnswer(ctx context.Context, tenantID, eventID, eventType string, payload any) error {
	if o == nil || o.log == nil || strings.TrimSpace(eventID) == "" {
		return errors.New("orchestrator: recovery check answers need an event id")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		event, err := o.log.Append(ctx, events.Event{ID: eventID, Type: eventType, TenantID: tenantID, Data: raw})
		if err != nil {
			return err
		}
		if event.ID != eventID || event.Type != eventType || event.TenantID != tenantID || !bytes.Equal(event.Data, raw) {
			return fmt.Errorf("%w: recovery check answer differs from the retained one", store.ErrIdempotencyConflict)
		}
		return o.proj.ApplyTx(ctx, tx, event)
	})
}
