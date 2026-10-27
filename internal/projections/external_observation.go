// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A180: an external observer (probectl or any monitor) reports what it saw at
// an endpoint, and receives rotation and rollback events. Registration is a
// tenant's configuration; each observation is matched, when it arrives, to
// what trstctl expected the endpoint to serve.
const (
	EventObserverRegistered  = "observer.registered"
	EventObserverUpdated     = "observer.updated"
	EventObservationRecorded = "observation.recorded"
)

// ObserverRegistered registers or (as observer.updated) replaces an
// observer's configuration.
type ObserverRegistered struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	EventsURL     string `json:"events_url,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
	Enabled       bool   `json:"enabled"`
}

// ObservationRecorded is one observation and the expectation it was compared
// with.
type ObservationRecorded struct {
	ID                  string    `json:"id"`
	ObserverID          string    `json:"observer_id"`
	Endpoint            string    `json:"endpoint"`
	Vantage             string    `json:"vantage,omitempty"`
	ObservedAt          time.Time `json:"observed_at"`
	Reachable           bool      `json:"reachable"`
	Health              string    `json:"health"`
	ServedFingerprint   string    `json:"served_fingerprint,omitempty"`
	ChainFingerprints   []string  `json:"chain_fingerprints,omitempty"`
	Detail              string    `json:"detail,omitempty"`
	ExpectedFingerprint string    `json:"expected_fingerprint,omitempty"`
	Verdict             string    `json:"verdict"`
}

var (
	observerNameRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
	fingerprintRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	observationHlth = map[string]bool{"healthy": true, "degraded": true, "unhealthy": true, "unknown": true}
	observationVerd = map[string]bool{
		store.ObservationMatch: true, store.ObservationMismatch: true,
		store.ObservationUnreachable: true, store.ObservationUnexpected: true,
	}
)

// ValidateObserverRegistered checks an observer's configuration: a name, an
// https events URL without credentials in it (or none), and a secret://
// credential reference (or none).
func ValidateObserverRegistered(pl ObserverRegistered) error {
	if pl.ID == "" || !observerNameRE.MatchString(pl.Name) {
		return errors.New("observer needs an id and a name of letters, digits, spaces, dots, dashes or underscores")
	}
	if pl.EventsURL != "" {
		u, err := url.Parse(pl.EventsURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return errors.New("observer events_url must be an https URL without credentials or a fragment")
		}
	}
	if pl.CredentialRef != "" && !strings.HasPrefix(pl.CredentialRef, "secret://") {
		return errors.New("observer credential_ref must be a secret:// reference")
	}
	return nil
}

// ValidateObservationRecorded checks an observation: a host:port endpoint,
// lowercase hex SHA-256 fingerprints, a health value and a verdict consistent
// with reachability.
func ValidateObservationRecorded(pl ObservationRecorded) error {
	if pl.ID == "" || pl.ObserverID == "" || pl.ObservedAt.IsZero() {
		return errors.New("observation needs an id, an observer and a time")
	}
	host, port, err := net.SplitHostPort(pl.Endpoint)
	if err != nil || host == "" || port == "" || len(pl.Endpoint) > 255 {
		return errors.New("observation endpoint must be host:port")
	}
	if !observationHlth[pl.Health] || !observationVerd[pl.Verdict] {
		return errors.New("observation health or verdict is not one this version records")
	}
	for _, fp := range append([]string{pl.ServedFingerprint, pl.ExpectedFingerprint}, pl.ChainFingerprints...) {
		if fp != "" && !fingerprintRE.MatchString(fp) {
			return errors.New("observation fingerprints are lowercase hex SHA-256")
		}
	}
	if !pl.Reachable && (pl.ServedFingerprint != "" || pl.Verdict != store.ObservationUnreachable) {
		return errors.New("an unreachable endpoint served nothing")
	}
	if len(pl.Vantage) > 128 || len(pl.Detail) > 1024 || len(pl.ChainFingerprints) > 16 {
		return errors.New("observation vantage, detail or chain is too long")
	}
	return nil
}

func (p *Projector) applyExternalObservationTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventObserverRegistered, EventObserverUpdated:
		var pl ObserverRegistered
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if err := ValidateObserverRegistered(pl); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		return true, p.store.ApplyExternalObserverUpsertedTx(ctx, tx, store.ExternalObserver{
			TenantID: e.TenantID, ID: pl.ID, Name: pl.Name, EventsURL: pl.EventsURL, CredentialRef: pl.CredentialRef,
			Enabled: pl.Enabled, UpdatedAt: e.Time, EventSequence: e.Sequence,
		})
	case EventObservationRecorded:
		var pl ObservationRecorded
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if err := ValidateObservationRecorded(pl); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		return true, p.store.ApplyExternalObservationRecordedTx(ctx, tx, store.ExternalObservation{
			TenantID: e.TenantID, ID: pl.ID, ObserverID: pl.ObserverID, Endpoint: pl.Endpoint, Vantage: pl.Vantage,
			ObservedAt: pl.ObservedAt, Reachable: pl.Reachable, Health: pl.Health, ServedFingerprint: pl.ServedFingerprint,
			ChainFingerprints: pl.ChainFingerprints, Detail: pl.Detail, ExpectedFingerprint: pl.ExpectedFingerprint,
			Verdict: pl.Verdict, RecordedAt: e.Time, EventSequence: e.Sequence,
		})
	}
	return false, nil
}
