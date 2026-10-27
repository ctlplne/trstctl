// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Finding kinds an external observation raises (A180).
const (
	// ExternalObservationMismatchKind: an observer saw an endpoint serve a
	// certificate other than the one trstctl deployed there.
	ExternalObservationMismatchKind = "external-observation-mismatch"
	// EndpointUnhealthyAfterRotationKind: an observer saw an endpoint
	// unhealthy or unreachable within ObservationRotationWindow after the
	// renewal that produced the certificate it should serve.
	EndpointUnhealthyAfterRotationKind = "endpoint-unhealthy-after-rotation"
)

// ObservationRotationWindow is how long after a renewal an unhealthy
// observation of its endpoint is attributed to that rotation.
const ObservationRotationWindow = 7 * 24 * time.Hour

var externalObservationNamespace = uuid.MustParse("b0e818ea-23cf-40e6-b06a-0e4c013fc214")

// ErrObserverUnavailable refuses an observation from an observer that is not
// registered and enabled in the tenant.
var ErrObserverUnavailable = errors.New("orchestrator: observer is not registered or not enabled")

// ErrObserverNameTaken refuses a second observer of the same name.
var ErrObserverNameTaken = errors.New("orchestrator: an observer of that name exists")

// ObserverInput is an observer's configuration as an operator submits it.
type ObserverInput struct {
	Name          string
	EventsURL     string
	CredentialRef string
	Enabled       bool
}

// RegisterObserver records a new external observer.
func (o *Orchestrator) RegisterObserver(ctx context.Context, tenantID string, in ObserverInput) (store.ExternalObserver, error) {
	existing, err := o.store.ListExternalObservers(ctx, tenantID)
	if err != nil {
		return store.ExternalObserver{}, err
	}
	name := strings.TrimSpace(in.Name)
	for _, observer := range existing {
		if observer.Name == name {
			return store.ExternalObserver{}, ErrObserverNameTaken
		}
	}
	return o.writeObserver(ctx, tenantID, projections.EventObserverRegistered, uuid.NewString(), in)
}

// UpdateObserver replaces an existing observer's configuration.
func (o *Orchestrator) UpdateObserver(ctx context.Context, tenantID, id string, in ObserverInput) (store.ExternalObserver, error) {
	current, err := o.store.GetExternalObserver(ctx, tenantID, id)
	if err != nil {
		return store.ExternalObserver{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name != current.Name {
		existing, err := o.store.ListExternalObservers(ctx, tenantID)
		if err != nil {
			return store.ExternalObserver{}, err
		}
		for _, observer := range existing {
			if observer.Name == name {
				return store.ExternalObserver{}, ErrObserverNameTaken
			}
		}
	}
	return o.writeObserver(ctx, tenantID, projections.EventObserverUpdated, current.ID, in)
}

func (o *Orchestrator) writeObserver(ctx context.Context, tenantID, eventType, id string, in ObserverInput) (store.ExternalObserver, error) {
	pl := projections.ObserverRegistered{
		ID: id, Name: strings.TrimSpace(in.Name), EventsURL: strings.TrimSpace(in.EventsURL),
		CredentialRef: strings.TrimSpace(in.CredentialRef), Enabled: in.Enabled,
	}
	if err := projections.ValidateObserverRegistered(pl); err != nil {
		return store.ExternalObserver{}, &InvalidObserverError{Reason: err.Error()}
	}
	data, err := json.Marshal(pl)
	if err != nil {
		return store.ExternalObserver{}, err
	}
	if _, err := o.emit(ctx, eventType, tenantID, data); err != nil {
		return store.ExternalObserver{}, err
	}
	return o.store.GetExternalObserver(ctx, tenantID, id)
}

// InvalidObserverError is a configuration or observation the projection would
// refuse.
type InvalidObserverError struct{ Reason string }

func (e *InvalidObserverError) Error() string { return "orchestrator: " + e.Reason }

// ObservationInput is one observation as an observer reports it.
type ObservationInput struct {
	ObserverID        string
	Endpoint          string
	Vantage           string
	ObservedAt        time.Time
	Reachable         bool
	Health            string
	ServedFingerprint string
	ChainFingerprints []string
	Detail            string
}

// RecordObservation records what an observer saw at an endpoint, compared with
// what trstctl expected the endpoint to serve: match, mismatch, unreachable,
// or unexpected when nothing trstctl verifies names the endpoint. A mismatch
// raises a finding, and so does an unhealthy or unreachable endpoint within
// ObservationRotationWindow after the renewal that produced the certificate it
// should serve. key makes a retried report converge on the same events.
func (o *Orchestrator) RecordObservation(ctx context.Context, tenantID, key string, in ObservationInput) (store.ExternalObservation, error) {
	observer, err := o.store.GetExternalObserver(ctx, tenantID, in.ObserverID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !observer.Enabled) {
		return store.ExternalObservation{}, ErrObserverUnavailable
	}
	if err != nil {
		return store.ExternalObservation{}, err
	}
	endpoint, err := normalizeObservedEndpoint(in.Endpoint)
	if err != nil {
		return store.ExternalObservation{}, &InvalidObserverError{Reason: err.Error()}
	}
	served := strings.ToLower(strings.TrimSpace(in.ServedFingerprint))
	chain := make([]string, 0, len(in.ChainFingerprints))
	for _, fp := range in.ChainFingerprints {
		chain = append(chain, strings.ToLower(strings.TrimSpace(fp)))
	}
	health := strings.ToLower(strings.TrimSpace(in.Health))
	if health == "" {
		health = "unknown"
	}
	expectation, expected, err := o.store.ExpectationForEndpoint(ctx, tenantID, endpoint)
	if err != nil {
		return store.ExternalObservation{}, err
	}
	pl := projections.ObservationRecorded{
		ID:         uuid.NewSHA1(externalObservationNamespace, []byte(tenantID+"\x00"+observer.ID+"\x00"+key)).String(),
		ObserverID: observer.ID, Endpoint: endpoint, Vantage: strings.TrimSpace(in.Vantage),
		ObservedAt: in.ObservedAt.UTC(), Reachable: in.Reachable, Health: health, ServedFingerprint: served,
		ChainFingerprints: chain, Detail: strings.TrimSpace(in.Detail), ExpectedFingerprint: expectation.Fingerprint,
	}
	switch {
	case !in.Reachable:
		pl.Verdict = store.ObservationUnreachable
	case !expected:
		pl.Verdict = store.ObservationUnexpected
	case served == expectation.Fingerprint:
		pl.Verdict = store.ObservationMatch
	default:
		pl.Verdict = store.ObservationMismatch
	}
	if err := projections.ValidateObservationRecorded(pl); err != nil {
		return store.ExternalObservation{}, &InvalidObserverError{Reason: err.Error()}
	}
	data, err := json.Marshal(pl)
	if err != nil {
		return store.ExternalObservation{}, err
	}
	if _, err := o.emitPreparedExact(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, "observation:"+pl.ID, "recorded"),
		Type: projections.EventObservationRecorded, TenantID: tenantID, Data: data}); err != nil {
		return store.ExternalObservation{}, err
	}
	switch {
	case pl.Verdict == store.ObservationMismatch:
		err = o.recordObservationFinding(ctx, tenantID, observer, pl, ExternalObservationMismatchKind, served, 80,
			fmt.Sprintf("%s saw %s serve a certificate other than the one trstctl deployed there", observer.Name, endpoint))
	case (health == "unhealthy" || !in.Reachable) && expected && expectation.RotatedAt != nil &&
		!pl.ObservedAt.Before(*expectation.RotatedAt) && pl.ObservedAt.Sub(*expectation.RotatedAt) <= ObservationRotationWindow:
		err = o.recordObservationFinding(ctx, tenantID, observer, pl, EndpointUnhealthyAfterRotationKind, expectation.Fingerprint, 70,
			fmt.Sprintf("%s saw %s %s after the renewal that produced the certificate it should serve", observer.Name, endpoint,
				map[bool]string{true: "unhealthy", false: "unreachable"}[in.Reachable]))
	}
	if err != nil {
		return store.ExternalObservation{}, err
	}
	observations, err := o.store.ListExternalObservations(ctx, tenantID, store.ExternalObservationFilter{ObserverID: observer.ID, Endpoint: endpoint, Limit: 500})
	if err != nil {
		return store.ExternalObservation{}, err
	}
	for _, observation := range observations {
		if observation.ID == pl.ID {
			return observation, nil
		}
	}
	return store.ExternalObservation{}, fmt.Errorf("orchestrator: observation %s was not projected", pl.ID)
}

// recordObservationFinding raises a finding under the product's own source for
// the observer, in a run of its own, keyed by the observation so a retried
// report converges.
func (o *Orchestrator) recordObservationFinding(ctx context.Context, tenantID string, observer store.ExternalObserver,
	pl projections.ObservationRecorded, kind, fingerprint string, risk int, reason string) error {
	sourceID := uuid.NewSHA1(externalObservationNamespace, []byte(tenantID+"\x00source\x00"+observer.ID)).String()
	if _, err := o.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
		ID: sourceID, Kind: "external_observation", Name: sourcecatalog.ExternalObserverSourcePrefix + observer.Name,
		Config: json.RawMessage(`{"check":"external_observation"}`),
	}); err != nil {
		return err
	}
	key := "observation:" + pl.ID
	runID := uuid.NewSHA1(externalObservationNamespace, []byte(tenantID+"\x00run\x00"+pl.ID)).String()
	queued, err := json.Marshal(projections.DiscoveryRunQueued{ID: runID, SourceID: sourceID, RequestedBy: "system:external-observation"})
	if err != nil {
		return err
	}
	if _, err := o.emitPreparedExact(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, key, "observation-run-queued"),
		Type: projections.EventDiscoveryRunQueued, TenantID: tenantID, Data: queued}); err != nil {
		return err
	}
	if err := o.StartDiscoveryRunWithEventID(ctx, tenantID, runID, DiscoveryRelayEventID(tenantID, key, "observation-run-started")); err != nil {
		return err
	}
	meta, err := json.Marshal(map[string]any{
		"observer": observer.Name, "observation_id": pl.ID, "vantage": pl.Vantage, "health": pl.Health,
		"reachable": pl.Reachable, "served_fingerprint": pl.ServedFingerprint, "expected_fingerprint": pl.ExpectedFingerprint,
		"verdict": pl.Verdict, "reason": reason,
	})
	if err != nil {
		return err
	}
	if _, err := o.RecordDiscoveryFindingWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "observation-finding"), store.DiscoveryFinding{
		RunID: runID, SourceID: sourceID, Kind: kind, Ref: pl.Endpoint, Provenance: "external-observation:" + pl.ID,
		Fingerprint: fingerprint, RiskScore: risk, Metadata: meta, DiscoveredAt: pl.ObservedAt,
	}); err != nil {
		return err
	}
	return o.CompleteDiscoveryRunWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "observation-run-completed"),
		store.DiscoveryRun{ID: runID, Status: "succeeded", Targets: 1, Discovered: 1})
}

// normalizeObservedEndpoint returns host:port with a lowercase host.
func normalizeObservedEndpoint(raw string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || host == "" || port == "" {
		return "", errors.New("observation endpoint must be host:port")
	}
	return net.JoinHostPort(strings.ToLower(host), port), nil
}
