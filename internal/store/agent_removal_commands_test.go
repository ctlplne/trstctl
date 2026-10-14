// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestAgentRemovalFirstWriterAndCompletedDenial(t *testing.T) {
	ctx := context.Background()
	st := newOperationApprovalStore(t)
	agentID := googleuuid.NewString()
	issuedAt := time.Now().UTC().Truncate(time.Microsecond)
	type result struct {
		command store.AgentRemovalCommand
		created bool
		err     error
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reasons := [...]string{"reason from a", "reason from b"}
			payload, err := json.Marshal(projections.AgentOffboarded{
				ID: agentID, Agent: "qa-ar3-first-writer", Reason: reasons[i],
			})
			if err != nil {
				results[i].err = err
				return
			}
			results[i].command, results[i].created, results[i].err = st.ClaimAgentRemovalCommand(
				ctx, store.AgentRemovalCommand{
					TenantID: tenantA, AgentID: agentID, Kind: "offboard",
					Event: events.Event{ID: googleuuid.NewString(), TenantID: tenantA,
						Type:          projections.EventAgentOffboarded,
						SchemaVersion: events.DefaultSchemaVersion, Time: issuedAt,
						Data: payload},
				})
		}(i)
	}
	wg.Wait()
	if results[0].err != nil || results[1].err != nil {
		t.Fatalf("competing removals: first=%v second=%v", results[0].err, results[1].err)
	}
	if results[0].created == results[1].created {
		t.Fatalf("first-writer result: %+v %+v; want exactly one created", results[0], results[1])
	}
	if results[0].command.Event.ID != results[1].command.Event.ID ||
		!bytes.Equal(results[0].command.Event.Data, results[1].command.Event.Data) {
		t.Fatalf("contenders did not receive the same canonical event")
	}
	if denied, err := st.AgentOffboarded(ctx, tenantA, agentID); err != nil || !denied {
		t.Fatalf("pending removal admitted agent: denied=%t err=%v", denied, err)
	}
	canonical := results[0].command.Event
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.CompleteAgentRemovalCommandTx(ctx, tx, canonical)
	}); err == nil {
		t.Fatal("pre-append completion erased the only recovery payload")
	}
	pending, err := st.ListPendingAgentRemovals(ctx, tenantA, 100)
	if err != nil || len(pending) != 1 || pending[0].Event.ID != canonical.ID {
		t.Fatalf("pre-append refusal lost pending recovery event: count=%d err=%v", len(pending), err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	retained, err := log.Append(ctx, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.CompleteAgentRemovalCommandTx(ctx, tx, retained)
	}); err != nil {
		t.Fatal(err)
	}
	if denied, err := st.AgentOffboarded(ctx, tenantA, agentID); err != nil || !denied {
		t.Fatalf("completed command lifted denial: denied=%t err=%v", denied, err)
	}
	other := store.AgentRemovalCommand{
		TenantID: tenantA, AgentID: googleuuid.NewString(), Kind: "offboard", Event: canonical,
	}
	if _, _, err := st.ClaimAgentRemovalCommand(ctx, other); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("event reused for another agent: %v, want conflict", err)
	}
}
