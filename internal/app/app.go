// Package app wires the event-sourced spine — the event log (AN-2), the
// projection workers, and the PostgreSQL read store (AN-1) — into application
// commands.
//
// For the S2.3 walking skeleton it provides a single, deliberately trivial
// command, RegisterTenant, that flows end-to-end: command -> event ->
// projection -> read. It is the thin layer the REST/gRPC API (S3.3) and the
// orchestrator (S3.2) will build on.
package app

import (
	"context"
	"encoding/json"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Service ties the spine together for application commands.
type Service struct {
	log   *events.Log
	store *store.Store
	proj  *projections.Projector
	idem  *orchestrator.Idempotency
	bulk  *bulkhead.Set
}

// New returns a Service over the given event log and store. It provisions an
// isolated, bounded worker pool per subsystem (AN-7); call Close to release them.
func New(log *events.Log, st *store.Store) *Service {
	return &Service{
		log:   log,
		store: st,
		proj:  projections.New(st),
		idem:  orchestrator.NewIdempotency(st),
		bulk:  bulkhead.Default(),
	}
}

// Submit runs task on the named subsystem's bounded pool (AN-7). It returns a
// structured *bulkhead.Rejected if that subsystem is saturated or unknown, so one
// subsystem's backlog can never starve another.
func (s *Service) Submit(subsystem string, task func()) error {
	return s.bulk.Submit(subsystem, task)
}

// Close releases the service's per-subsystem worker pools, draining queued work.
// It is safe to call more than once.
func (s *Service) Close() { s.bulk.Close() }

// RegisterTenant emits a tenant.registered event and projects THAT ONE event into
// the read model, then returns. The projection is driven synchronously here so the
// command is deterministic (a fresh read sees the tenant immediately); a real
// deployment also runs the tailing projection worker off the same stream.
//
// It projects only the just-appended event via proj.Apply (SPINE-008), not a full
// log replay (proj.Project): the previous shape re-applied the WHOLE log inside the
// idempotency transaction on every call, so the bootstrap's cost grew with the
// lifetime event count — an O(total-log) write-path anti-pattern. Apply is the same
// projector logic a rebuild uses (an idempotent upsert), so live state and a
// replayed state still agree, and the read model stays a pure projection of the log
// (AN-2). This mirrors orchestrator.emit, which projects the single appended event.
//
// The whole command runs under idempotencyKey (AN-5): a replay with the same key
// returns the original result without emitting a second event, and concurrent
// duplicates collapse to one registration.
//
//trstctl:mutation
func (s *Service) RegisterTenant(ctx context.Context, tenantID, name, idempotencyKey string) error {
	_, err := s.idem.Do(ctx, tenantID, idempotencyKey, func(ctx context.Context) ([]byte, error) {
		data, err := json.Marshal(struct {
			Name string `json:"name"`
		}{Name: name})
		if err != nil {
			return nil, err
		}
		ev, err := s.log.Append(ctx, events.Event{
			Type:     "tenant.registered",
			TenantID: tenantID,
			Data:     data,
		})
		if err != nil {
			return nil, err
		}
		if err := s.proj.Apply(ctx, ev); err != nil {
			return nil, err
		}
		return data, nil
	})
	return err
}

// GetTenant reads a tenant from the read model in its own tenant context.
func (s *Service) GetTenant(ctx context.Context, tenantID string) (store.Tenant, error) {
	return s.store.GetTenant(ctx, tenantID)
}
