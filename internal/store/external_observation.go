// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ExternalObserver is a monitor outside trstctl (probectl or any other) that
// reports what it saw at endpoints and receives rotation and rollback events
// (A180).
type ExternalObserver struct {
	TenantID string
	ID       string
	Name     string
	// EventsURL receives rotation and rollback events; empty receives none.
	EventsURL string
	// CredentialRef names the tenant secret whose value signs each event
	// (HMAC-SHA256); empty sends events unsigned.
	CredentialRef string
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	EventSequence uint64
}

// ExternalObservation is one report of what an observer saw at an endpoint,
// with what trstctl expected the endpoint to serve when it arrived.
type ExternalObservation struct {
	TenantID            string
	ID                  string
	ObserverID          string
	ObserverName        string
	Endpoint            string
	Vantage             string
	ObservedAt          time.Time
	Reachable           bool
	Health              string
	ServedFingerprint   string
	ChainFingerprints   []string
	Detail              string
	ExpectedFingerprint string
	Verdict             string
	RecordedAt          time.Time
	EventSequence       uint64
}

// External observation verdicts.
const (
	ObservationMatch       = "match"
	ObservationMismatch    = "mismatch"
	ObservationUnreachable = "unreachable"
	// ObservationUnexpected: nothing trstctl deployed names this endpoint, so
	// there was nothing to compare with.
	ObservationUnexpected = "unexpected"
)

// ObserverEventDestination is the outbox destination that delivers rotation
// and rollback events to an observer.
const ObserverEventDestination = "observer.event"

// ApplyExternalObserverUpsertedTx projects observer.registered and
// observer.updated.
func (s *Store) ApplyExternalObserverUpsertedTx(ctx context.Context, tx pgx.Tx, o ExternalObserver) error {
	// The table is also unique on (tenant, name): serialize applies of one
	// observer so a concurrent replay takes the ON CONFLICT path.
	if err := lockUpsertArbiterTx(ctx, tx, "external_observers", o.TenantID, o.ID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO external_observers (tenant_id, id, name, events_url, credential_ref, enabled, created_at, updated_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET name = EXCLUDED.name, events_url = EXCLUDED.events_url, credential_ref = EXCLUDED.credential_ref,
		        enabled = EXCLUDED.enabled, updated_at = EXCLUDED.updated_at, event_sequence = EXCLUDED.event_sequence
		  WHERE external_observers.event_sequence < EXCLUDED.event_sequence`,
		o.TenantID, o.ID, o.Name, o.EventsURL, o.CredentialRef, o.Enabled, o.UpdatedAt, int64(o.EventSequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

// ApplyExternalObservationRecordedTx projects observation.recorded. A replay of
// the same event converges.
func (s *Store) ApplyExternalObservationRecordedTx(ctx context.Context, tx pgx.Tx, o ExternalObservation) error {
	chain := o.ChainFingerprints
	if chain == nil {
		chain = []string{}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO external_observations (tenant_id, id, observer_id, endpoint, vantage, observed_at, reachable, health,
		        served_fingerprint, chain_fingerprints, detail, expected_fingerprint, verdict, recorded_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		o.TenantID, o.ID, o.ObserverID, o.Endpoint, o.Vantage, o.ObservedAt, o.Reachable, o.Health,
		o.ServedFingerprint, chain, o.Detail, o.ExpectedFingerprint, o.Verdict, o.RecordedAt,
		int64(o.EventSequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

const externalObserverColumns = `id::text, tenant_id::text, name, events_url, credential_ref, enabled, created_at, updated_at, event_sequence`

func scanExternalObserver(row pgx.Row, o *ExternalObserver) error {
	var seq int64
	if err := row.Scan(&o.ID, &o.TenantID, &o.Name, &o.EventsURL, &o.CredentialRef, &o.Enabled, &o.CreatedAt, &o.UpdatedAt, &seq); err != nil {
		return err
	}
	o.EventSequence = uint64(seq) // #nosec G115 -- non-negative by constraint (CWE-190)
	return nil
}

// GetExternalObserver returns one of the tenant's observers.
func (s *Store) GetExternalObserver(ctx context.Context, tenantID, id string) (ExternalObserver, error) {
	var o ExternalObserver
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanExternalObserver(tx.QueryRow(ctx,
			`SELECT `+externalObserverColumns+` FROM external_observers WHERE tenant_id = $1 AND id = $2`, tenantID, id), &o)
	})
	return o, err
}

// ListExternalObservers returns the tenant's observers by name.
func (s *Store) ListExternalObservers(ctx context.Context, tenantID string) ([]ExternalObserver, error) {
	var out []ExternalObserver
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+externalObserverColumns+` FROM external_observers WHERE tenant_id = $1 ORDER BY name, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o ExternalObserver
			if err := scanExternalObserver(rows, &o); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

const externalObservationColumns = `o.id::text, o.tenant_id::text, o.observer_id::text, coalesce(obs.name, ''), o.endpoint, o.vantage,
        o.observed_at, o.reachable, o.health, o.served_fingerprint, o.chain_fingerprints, o.detail,
        o.expected_fingerprint, o.verdict, o.recorded_at, o.event_sequence`

func scanExternalObservation(row pgx.Row, o *ExternalObservation) error {
	var seq int64
	if err := row.Scan(&o.ID, &o.TenantID, &o.ObserverID, &o.ObserverName, &o.Endpoint, &o.Vantage,
		&o.ObservedAt, &o.Reachable, &o.Health, &o.ServedFingerprint, &o.ChainFingerprints, &o.Detail,
		&o.ExpectedFingerprint, &o.Verdict, &o.RecordedAt, &seq); err != nil {
		return err
	}
	o.EventSequence = uint64(seq) // #nosec G115 -- non-negative by constraint (CWE-190)
	return nil
}

// ExternalObservationFilter narrows ListExternalObservations.
type ExternalObservationFilter struct {
	ObserverID  string
	Endpoint    string
	Fingerprint string // served or expected
	Limit       int
}

// ListExternalObservations returns the tenant's observations, newest first.
func (s *Store) ListExternalObservations(ctx context.Context, tenantID string, f ExternalObservationFilter) ([]ExternalObservation, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	var out []ExternalObservation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+externalObservationColumns+`
			   FROM external_observations o
			   LEFT JOIN external_observers obs ON obs.tenant_id = o.tenant_id AND obs.id = o.observer_id
			  WHERE o.tenant_id = $1
			    AND ($2 = '' OR o.observer_id::text = $2)
			    AND ($3 = '' OR o.endpoint = $3)
			    AND ($4 = '' OR o.served_fingerprint = $4 OR o.expected_fingerprint = $4)
			  ORDER BY o.observed_at DESC, o.id
			  LIMIT $5`, tenantID, f.ObserverID, f.Endpoint, f.Fingerprint, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o ExternalObservation
			if err := scanExternalObservation(rows, &o); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// EndpointExpectation is what trstctl expects an endpoint to serve.
type EndpointExpectation struct {
	EndpointID  string
	Fingerprint string
	// RotatedAt is when the renewal that produced Fingerprint completed; nil
	// when no completed renewal produced it.
	RotatedAt *time.Time
}

// ExpectationForEndpoint resolves what an endpoint, named host:port, is
// expected to serve: the expectation its newest endpoint verification
// carries. Not found when nothing trstctl verifies names the address.
func (s *Store) ExpectationForEndpoint(ctx context.Context, tenantID, address string) (EndpointExpectation, bool, error) {
	var out EndpointExpectation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT endpoint_id, expected_fingerprint FROM endpoint_verifications
			  WHERE tenant_id = $1 AND address = $2 AND expected_fingerprint <> ''
			  ORDER BY last_checked_at DESC, vantage LIMIT 1`, tenantID, address).Scan(&out.EndpointID, &out.Fingerprint); err != nil {
			return err
		}
		var rotated time.Time
		err := tx.QueryRow(ctx,
			`SELECT completed_at FROM lifecycle_rotation_runs
			  WHERE tenant_id = $1 AND successor_fingerprint = $2 AND status = 'succeeded' AND completed_at IS NOT NULL
			  ORDER BY completed_at DESC LIMIT 1`, tenantID, out.Fingerprint).Scan(&rotated)
		switch {
		case err == nil:
			out.RotatedAt = &rotated
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return EndpointExpectation{}, false, nil
	}
	if err != nil {
		return EndpointExpectation{}, false, err
	}
	return out, true, nil
}

// EnqueueObserverEventsTx queues one event for every enabled observer with an
// events URL, in the transaction that records what the event reports, so the
// effect is as durable as the fact (AN outbox). eventKey identifies the event;
// each observer's row is keyed by it, so a replay converges on the row the
// first projection queued. The payload is not compared: it lists endpoints read
// from projections that a rebuild may not have reached yet, and a rebuild must
// not fail on that.
func (s *Store) EnqueueObserverEventsTx(ctx context.Context, tx pgx.Tx, tenantID, eventKey string, payload func(observerID string) ([]byte, error)) error {
	rows, err := tx.Query(ctx,
		`SELECT id::text FROM external_observers
		  WHERE tenant_id = $1 AND enabled AND events_url <> ''
		  ORDER BY id`, tenantID)
	if err != nil {
		return err
	}
	var observers []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		observers = append(observers, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, observerID := range observers {
		body, err := payload(observerID)
		if err != nil {
			return err
		}
		key := "observer-event:" + observerID + ":" + eventKey
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2)`,
			tenantID, key).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
			 VALUES ($1, $2, $2, $3, $4)`, tenantID, ObserverEventDestination, body, key); err != nil {
			return fmt.Errorf("store: enqueue observer event: %w", err)
		}
	}
	return nil
}

// ObserverEvent is what an observer receives: a rotation or rollback, the
// certificate the affected endpoints should now serve, and those endpoints.
// ID is stable per event, so an observer can drop a redelivery.
type ObserverEvent struct {
	ID                  string    `json:"id"`
	Type                string    `json:"type"`
	TenantID            string    `json:"tenant_id"`
	OccurredAt          time.Time `json:"occurred_at"`
	IdentityID          string    `json:"identity_id,omitempty"`
	PreviousFingerprint string    `json:"previous_fingerprint,omitempty"`
	CurrentFingerprint  string    `json:"current_fingerprint"`
	Endpoints           []string  `json:"endpoints"`
	Targets             []string  `json:"targets"`
	RotationRunID       string    `json:"rotation_run_id,omitempty"`
	RollbackReceiptID   string    `json:"rollback_receipt_id,omitempty"`
}

// Observer event types.
const (
	ObserverEventRotationCompleted = "rotation.completed"
	ObserverEventRollbackCompleted = "rollback.completed"
)

// ObserverEventFreshness bounds how old an event may be when its projection
// runs and still be sent: a live event is projected as it is recorded, while a
// rebuild replaying history must not resend old rotations.
const ObserverEventFreshness = 24 * time.Hour

// QueueObserverEventTx completes ev with the endpoints and targets it concerns
// — the addresses trstctl verifies for either certificate, and the connector
// targets that delivered them — and queues it for every enabled observer,
// unless it is older than ObserverEventFreshness at now.
func (s *Store) QueueObserverEventTx(ctx context.Context, tx pgx.Tx, ev ObserverEvent, now time.Time) error {
	if now.Sub(ev.OccurredAt) > ObserverEventFreshness {
		return nil
	}
	fingerprints := []string{ev.CurrentFingerprint}
	if ev.PreviousFingerprint != "" {
		fingerprints = append(fingerprints, ev.PreviousFingerprint)
	}
	ev.Endpoints, ev.Targets = []string{}, []string{}
	rows, err := tx.Query(ctx,
		`SELECT DISTINCT address FROM endpoint_verifications
		  WHERE tenant_id = $1 AND expected_fingerprint = ANY($2) AND address <> ''
		  ORDER BY address`, ev.TenantID, fingerprints)
	if err != nil {
		return err
	}
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			rows.Close()
			return err
		}
		ev.Endpoints = append(ev.Endpoints, address)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = tx.Query(ctx,
		`SELECT DISTINCT target FROM connector_delivery_receipts
		  WHERE tenant_id = $1 AND fingerprint = ANY($2) AND target <> ''
		  ORDER BY target`, ev.TenantID, fingerprints)
	if err != nil {
		return err
	}
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			rows.Close()
			return err
		}
		ev.Targets = append(ev.Targets, target)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	event, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return s.EnqueueObserverEventsTx(ctx, tx, ev.TenantID, ev.ID, func(observerID string) ([]byte, error) {
		return json.Marshal(struct {
			ObserverID string          `json:"observer_id"`
			Event      json.RawMessage `json:"event"`
		}{observerID, event})
	})
}
