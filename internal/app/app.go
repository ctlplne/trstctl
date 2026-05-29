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

	"certctl.io/certctl/internal/events"
	"certctl.io/certctl/internal/projections"
	"certctl.io/certctl/internal/store"
)

// Service ties the spine together for application commands.
type Service struct {
	log   *events.Log
	store *store.Store
	proj  *projections.Projector
}

// New returns a Service over the given event log and store.
func New(log *events.Log, st *store.Store) *Service {
	return &Service{log: log, store: st, proj: projections.New(st)}
}

// RegisterTenant emits a tenant.registered event and projects it into the read
// model, then returns. The projection is driven synchronously here so the
// walking skeleton is deterministic; a real deployment runs projections as a
// background worker off the same stream.
func (s *Service) RegisterTenant(ctx context.Context, tenantID, name string) error {
	data, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: name})
	if err != nil {
		return err
	}
	if _, err := s.log.Append(ctx, events.Event{
		Type:     "tenant.registered",
		TenantID: tenantID,
		Data:     data,
	}); err != nil {
		return err
	}
	return s.proj.Project(ctx, s.log)
}

// GetTenant reads a tenant from the read model in its own tenant context.
func (s *Service) GetTenant(ctx context.Context, tenantID string) (store.Tenant, error) {
	return s.store.GetTenant(ctx, tenantID)
}
