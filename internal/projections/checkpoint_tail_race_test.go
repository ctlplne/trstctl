// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
)

// A live tail may advance while catch-up replays its captured history window.
// Revocation invokes catch-up on a running server, so ordinary event traffic
// must not be mistaken for a lost event stream. Reset provides a deterministic
// pause after the head was captured; the real PostgreSQL/NATS tail does the work.
func TestProjectCatchUpAcceptsTailBeyondCapturedHead(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	base := projections.New(s)
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	if err := base.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}

	worker := projections.NewTailWorker(log, base, nil, time.Second)
	runErr := make(chan error, 1)
	go func() { runErr <- worker.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-runErr:
		case <-time.After(5 * time.Second):
			t.Error("tail worker did not stop")
		}
	}()

	var appended uint64
	extension := &catchUpResetHook{reset: func(resetCtx context.Context) error {
		e, err := log.Append(resetCtx, events.Event{
			Type: projections.EventOwnerCreated, TenantID: tenantA,
			Data: ownerCreated("00000000-0000-0000-0000-0000000000e1", "tailed during catch-up"),
		})
		if err != nil {
			return err
		}
		appended = e.Sequence
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			checkpoint, err := s.ProjectionCheckpoint(resetCtx)
			if err != nil {
				return err
			}
			if checkpoint >= appended {
				return nil
			}
			select {
			case <-resetCtx.Done():
				return resetCtx.Err()
			case <-ticker.C:
			}
		}
	}}
	if err := projections.New(s, projections.WithEventProjection(extension)).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("live tail progress was mistaken for missing history: %v", err)
	}
	checkpoint, err := s.ProjectionCheckpoint(ctx)
	if err != nil || checkpoint != appended {
		t.Fatalf("checkpoint = %d, error = %v; want preserved tail sequence %d", checkpoint, err, appended)
	}
	if got := ownerCount(t, s, tenantA); got != 1 {
		t.Fatalf("tail owner count = %d, want 1", got)
	}
	if err := base.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("subsequent catch-up: %v", err)
	}
}

func TestProjectCatchUpRefusesMissingHistoryBeforeReset(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	if err := projections.New(s).ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a database restored with a watermark beyond retained NATS history.
	if err := s.AdvanceProjectionCheckpoint(ctx, head+1); err != nil {
		t.Fatal(err)
	}
	reset := false
	extension := &catchUpResetHook{reset: func(context.Context) error { reset = true; return nil }}
	err = projections.New(s, projections.WithEventProjection(extension)).ProjectCatchUp(ctx, log)
	want := fmt.Sprintf("checkpoint %d is beyond event history head %d", head+1, head)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("missing-history error = %v, want %q", err, want)
	}
	if reset {
		t.Error("extension was reset before missing history was refused")
	}
	if checkpoint, err := s.ProjectionCheckpoint(ctx); err != nil || checkpoint != head+1 {
		t.Fatalf("missing-history checkpoint changed: %d, %v", checkpoint, err)
	}
}

type catchUpResetHook struct{ reset func(context.Context) error }

func (*catchUpResetHook) Name() string                                 { return "catch-up-tail-interleave" }
func (p *catchUpResetHook) Reset(ctx context.Context) error            { return p.reset(ctx) }
func (*catchUpResetHook) Apply(context.Context, eventspec.Event) error { return nil }
