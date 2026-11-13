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

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Annotating a leaked-secret finding at its provider (A174).
//
// A third-party scan finds a credential in a Slack export, a Jira export, a
// CI log or a container image. An annotation tells the people at that place:
// a reply in the Slack thread, a comment on the issue, a commit status on the
// CI run's commit, a referrer on the image. Each request is durable: the
// finding records it as queued and one control-plane outbox row carries it
// in the same transaction; the row's executor writes at the provider and the
// finding then records what the provider confirmed.

// DestinationScanAnnotation is the control-plane row that writes the
// annotation.
const DestinationScanAnnotation = "scan.annotation"

// FindingActionAnnotate is the provider action an annotation records under.
const FindingActionAnnotate = "annotate"

// FindingActionResolveAnnotation is the provider action that settles an
// annotation once its finding is resolved (A174-L1).
const FindingActionResolveAnnotation = "resolve_annotation"

// Annotation statuses, as the finding records them.
const (
	AnnotationQueued         = "queued"
	AnnotationConfirmed      = "confirmed"
	AnnotationAlreadyPresent = "already_present"
	AnnotationFailed         = "failed"
	// AnnotationUnconfirmed is a write that reached the provider whose answer
	// was lost (A174-L4); the next attempt settles it.
	AnnotationUnconfirmed = "unconfirmed"
	// A174-L1: a settled annotation.
	AnnotationResolved        = "resolved"
	AnnotationAlreadyResolved = "already_resolved"
)

var scanAnnotationNamespace = uuid.MustParse("4c1d74a1-a174-4174-8174-a174a174a174")

// FindingAnnotationIntent is the row's payload: identifiers only; the
// provider token stays behind the source's reference.
type FindingAnnotationIntent struct {
	RequestID  string            `json:"request_id"`
	FindingID  string            `json:"finding_id"`
	SourceID   string            `json:"source_id"`
	Provider   string            `json:"provider"`
	Rule       string            `json:"rule"`
	Location   string            `json:"location,omitempty"`
	DetectedAt string            `json:"detected_at,omitempty"`
	Object     map[string]string `json:"object"`
	Reason     string            `json:"reason,omitempty"`
	// Action is FindingActionAnnotate when empty, or
	// FindingActionResolveAnnotation to settle the annotation ProviderRef
	// names once the finding is resolved (A174-L1).
	Action      string `json:"action,omitempty"`
	ProviderRef string `json:"provider_ref,omitempty"`
}

// action is the provider action the intent records under.
func (in FindingAnnotationIntent) action() string {
	if in.Action == FindingActionResolveAnnotation {
		return FindingActionResolveAnnotation
	}
	return FindingActionAnnotate
}

// QueueFindingAnnotation records the request on the finding and queues its
// row in one tenant transaction. requestKey is the durable request identity:
// a retried request converges on the same request and row.
func (o *Orchestrator) QueueFindingAnnotation(ctx context.Context, tenantID, requestKey, actor string, in FindingAnnotationIntent) (FindingAnnotationIntent, error) {
	if o.outbox == nil {
		return FindingAnnotationIntent{}, errors.New("orchestrator: scan annotation outbox is unavailable")
	}
	if strings.TrimSpace(in.FindingID) == "" || strings.TrimSpace(in.SourceID) == "" || strings.TrimSpace(in.Provider) == "" || len(in.Object) == 0 {
		return FindingAnnotationIntent{}, errors.New("orchestrator: scan annotation is incomplete")
	}
	in.RequestID = uuid.NewSHA1(scanAnnotationNamespace, []byte(tenantID+"\x00"+requestKey)).String()
	queued, err := json.Marshal(projections.DiscoveryFindingProviderAction{
		FindingID: in.FindingID, Action: FindingActionAnnotate, Status: AnnotationQueued, Provider: in.Provider,
		RequestID: in.RequestID, Reason: in.Reason, Actor: actor,
	})
	if err != nil {
		return FindingAnnotationIntent{}, err
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return FindingAnnotationIntent{}, err
	}
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ev, err := o.log.Append(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, requestKey, "scan-annotation-queued"),
			Type: projections.EventDiscoveryFindingProviderAction, TenantID: tenantID, Data: queued})
		if err != nil {
			return err
		}
		if ev.Type != projections.EventDiscoveryFindingProviderAction || ev.TenantID != tenantID || !bytes.Equal(ev.Data, queued) {
			return fmt.Errorf("%w: scan annotation request differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: DestinationScanAnnotation,
			IdempotencyKey: "scan-annotation:" + in.RequestID, Payload: payload,
			EffectLane: "scan-annotation:" + in.Provider, RequiredAgentRole: "control_plane",
		})
		return err
	})
	return in, err
}

// RecordFindingAnnotation records what the provider confirmed, under an id
// derived from the request so a redelivered row converges.
// RecordFindingAnnotationUnconfirmed records that an attempt's write reached
// the provider and its answer was lost (A174-L4), under an id of its own, so
// the retry that settles it can tell and the final result still converges.
func (o *Orchestrator) RecordFindingAnnotationUnconfirmed(ctx context.Context, tenantID string, in FindingAnnotationIntent, detail string) error {
	payload, err := json.Marshal(projections.DiscoveryFindingProviderAction{
		FindingID: in.FindingID, Action: in.action(), Status: AnnotationUnconfirmed, Provider: in.Provider,
		Detail: detail, RequestID: in.RequestID,
	})
	if err != nil {
		return err
	}
	_, err = o.emitPrepared(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, in.RequestID, "scan-annotation-unconfirmed"),
		Type: projections.EventDiscoveryFindingProviderAction, TenantID: tenantID, Data: payload})
	return err
}

func (o *Orchestrator) RecordFindingAnnotation(ctx context.Context, tenantID string, in FindingAnnotationIntent, status, providerRef, detail string) error {
	payload, err := json.Marshal(projections.DiscoveryFindingProviderAction{
		FindingID: in.FindingID, Action: in.action(), Status: status, Provider: in.Provider,
		Detail: detail, ProviderRef: providerRef, RequestID: in.RequestID,
	})
	if err != nil {
		return err
	}
	_, err = o.emitPrepared(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, in.RequestID, "scan-annotation-result"),
		Type: projections.EventDiscoveryFindingProviderAction, TenantID: tenantID, Data: payload})
	return err
}
