// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A65: an agent audit event whose publish the bus did not acknowledge is not
// lost. Its identity is fixed before the first attempt, the failure queues the
// same event on a control-plane outbox row, the dispatcher re-appends it under
// that identity, and a redelivery is deduplicated by the stream rather than
// recorded twice. A deterministic refusal is logged, not retried.
func TestServedAgentAuditEventsRetryThroughTheOutboxAfterAnUnacknowledgedPublish(t *testing.T) {
	ctx := context.Background()
	const eventType = "agent.jobs.role_refused"
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"endpoint.renew"}, func(*Deps) {})
	svc, ok := h.srv.agentServiceForTest()
	if !ok {
		t.Fatal("agent service is not assembled")
	}
	var (
		mu       sync.Mutex
		failures []error
		attempts int
	)
	svc.appendAuditEvent = func(ctx context.Context, e events.Event) (events.Event, error) {
		mu.Lock()
		attempts++
		if len(failures) > 0 {
			err := failures[0]
			failures = failures[1:]
			mu.Unlock()
			return events.Event{}, err
		}
		mu.Unlock()
		return h.log.Append(ctx, e)
	}
	failNext := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		failures = append(failures, err)
	}
	recorded := func() []events.Event {
		t.Helper()
		var out []events.Event
		if err := h.log.Replay(ctx, 1, func(e events.Event) error {
			if e.Type == eventType && e.TenantID == h.tenant {
				out = append(out, e)
			}
			return nil
		}); err != nil {
			t.Fatalf("replay: %v", err)
		}
		return out
	}
	type retryRow struct {
		role    string
		payload agentAuditRetryPayload
	}
	retryRows := func() []retryRow {
		t.Helper()
		var rows []retryRow
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			result, err := tx.Query(ctx, `SELECT required_agent_role, payload FROM outbox WHERE tenant_id=$1 AND destination=$2 ORDER BY id`, h.tenant, orchestrator.DestinationAgentAuditRetry)
			if err != nil {
				return err
			}
			defer result.Close()
			for result.Next() {
				var row retryRow
				var raw []byte
				if err := result.Scan(&row.role, &raw); err != nil {
					return err
				}
				if err := json.Unmarshal(raw, &row.payload); err != nil {
					return err
				}
				rows = append(rows, row)
			}
			return result.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	// A network relay reaching for host work is refused and the reach recorded.
	reach := func() {
		t.Helper()
		if _, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.renew"}, Limit: 1, LeaseSeconds: 60}); err != nil {
			t.Fatalf("claim: %v", err)
		}
	}

	// 1. The bus does not acknowledge the first publish: nothing is in the log,
	// one control-plane retry row carries the event under its fixed identity.
	failNext(fmt.Errorf("nats: timeout: %w", events.ErrPublish))
	reach()
	if got := recorded(); len(got) != 0 {
		t.Fatalf("events after an unacknowledged publish = %d, want none yet", len(got))
	}
	rows := retryRows()
	if len(rows) != 1 || rows[0].role != "control_plane" {
		t.Fatalf("retry rows = %+v, want one control_plane row", rows)
	}
	queued := rows[0].payload
	if queued.ID == "" || queued.Type != eventType || queued.TenantID != h.tenant || !strings.Contains(string(queued.Data), `"refused_kinds"`) {
		t.Fatalf("queued retry payload = %+v", queued)
	}

	// 2. The dispatcher re-appends it under the same identity.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	got := recorded()
	if len(got) != 1 || got[0].ID != queued.ID || !strings.Contains(string(got[0].Data), `"endpoint.renew"`) {
		t.Fatalf("events after drain = %+v, want the queued event once under id %s", got, queued.ID)
	}

	// 3. A redelivery of the same row is the same message: the stream
	// deduplicates it and the handler reports success.
	dispatcher, ok := h.srv.obHandler.(*issuanceDispatcher)
	if !ok {
		t.Fatal("served outbox handler is not the issuance dispatcher")
	}
	raw, _ := json.Marshal(queued)
	if err := dispatcher.handleAgentAuditRetry(ctx, orchestrator.Message{TenantID: h.tenant, Destination: orchestrator.DestinationAgentAuditRetry, Payload: raw}); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if got := recorded(); len(got) != 1 {
		t.Fatalf("events after a redelivery = %d, want still one", len(got))
	}
	// A row for another tenant's event is refused, not appended.
	if err := dispatcher.handleAgentAuditRetry(ctx, orchestrator.Message{TenantID: "22222222-2222-2222-2222-222222222222", Destination: orchestrator.DestinationAgentAuditRetry, Payload: raw}); err == nil {
		t.Fatal("a retry row whose tenant differs from its event was accepted")
	}

	// 4. A deterministic refusal (the log rejecting the envelope) is not
	// retried: no new row, no new event.
	failNext(errors.New("events: tenant_id is required (AN-1)"))
	reach()
	if rows := retryRows(); len(rows) != 1 {
		t.Fatalf("retry rows after a deterministic refusal = %d, want still one", len(rows))
	}
	if got := recorded(); len(got) != 1 {
		t.Fatalf("events after a deterministic refusal = %d, want still one", len(got))
	}

	// 5. An acknowledged publish needs no row.
	reach()
	if got := recorded(); len(got) != 2 {
		t.Fatalf("events after a clean publish = %d, want two", len(got))
	}
	if rows := retryRows(); len(rows) != 1 {
		t.Fatalf("retry rows after a clean publish = %d, want still one", len(rows))
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 3 {
		t.Fatalf("direct append attempts = %d, want one per reach", attempts)
	}
}
