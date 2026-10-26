// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/transit"
)

// transitFactReconcileInterval is how often the leader records the transit
// lifecycle facts the event log lacks (A126).
const transitFactReconcileInterval = 10 * time.Minute

// transitFactRecorder keeps transit lifecycle facts in the event log (A126).
// Each fact is appended under its fact ID as the event ID and projected at
// once, so the versions listing reads its own writes; the projection tail
// applies the same event again harmlessly.
type transitFactRecorder struct {
	log       *events.Log
	store     *store.Store
	projector *projections.Projector
}

var _ transit.FactRecorder = transitFactRecorder{}

func (r transitFactRecorder) Recorded(ctx context.Context, tenantID string, factIDs []string) (map[string]time.Time, error) {
	return r.store.TransitKeyFactsRecorded(ctx, tenantID, factIDs)
}

// Record appends the fact unless the log already holds an event with its
// ID, then projects that event. An event under the ID that is not this
// tenant's fact is refused rather than projected.
func (r transitFactRecorder) Record(ctx context.Context, tenantID string, fact transit.Fact) error {
	ev, found, err := r.log.EventByID(ctx, fact.ID)
	if err != nil {
		return fmt.Errorf("look up the fact's event: %w", err)
	}
	if found {
		if ev.TenantID != tenantID || ev.Type != fact.EventType() {
			return fmt.Errorf("event %s is not this tenant's %s fact", fact.ID, fact.EventType())
		}
	} else {
		data, err := json.Marshal(projections.TransitKeyFact{Key: fact.Key, Kind: string(fact.Kind), Version: fact.Version})
		if err != nil {
			return err
		}
		ev, err = r.log.Append(ctx, events.Event{
			ID: fact.ID, Type: fact.EventType(), TenantID: tenantID,
			SchemaVersion: transit.FactSchemaVersion, Data: data,
		})
		if err != nil {
			return fmt.Errorf("append the fact: %w", err)
		}
	}
	return r.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return r.projector.ApplyTx(ctx, tx, ev)
	})
}

// RunTransitFactReconcile records, on the leader, the transit lifecycle facts
// the event log lacks (A126): a fact whose append failed after its version
// was saved, and the versions saved before facts existed. It runs at start and
// then on a fixed interval; a tenant whose keyring cannot be opened (a sealed
// tenant) is retried on the next pass.
func (s *Server) RunTransitFactReconcile(ctx context.Context) {
	if s.transit == nil || s.store == nil {
		return
	}
	s.transitFactReconcileOnce(ctx)
	t := time.NewTicker(transitFactReconcileInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.transitFactReconcileOnce(ctx)
		}
	}
}

func (s *Server) transitFactReconcileOnce(ctx context.Context) {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		s.logger.Warn("transit fact reconcile could not list tenants", slog.String("error", err.Error()))
		return
	}
	failed := 0
	for _, tenant := range tenants {
		if ctx.Err() != nil {
			return
		}
		tenantCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := s.transit.ReconcileFacts(tenantCtx, tenant.TenantID)
		cancel()
		if err != nil {
			failed++
		}
	}
	if failed > 0 {
		s.logger.Warn("transit lifecycle facts could not be reconciled for some tenants; retrying next pass",
			slog.Int("tenants", failed))
	}
}
