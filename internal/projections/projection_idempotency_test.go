// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestCertificateProjectionRejectsIDReuseAsDomainCorruption distinguishes a
// legitimate at-least-once replay from a corrupt event that reuses one UUID for
// different certificate bytes. The sink must return a stable domain error; a raw
// certificates_pkey error is both opaque and indistinguishable from the live
// inline/tail race above.
func TestCertificateProjectionRejectsIDReuseAsDomainCorruption(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	log := openLog(t)
	proj := projections.New(s)
	const certID = "10000000-0000-4000-8000-000000000098"
	first := projectorEvent(t, projections.EventCertificateRecorded, projections.CertificateRecorded{
		ID: certID, Subject: "CN=first.example", Fingerprint: "sha256:first", Serial: "98",
	})
	first, err := log.Append(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := proj.Apply(ctx, first); err != nil {
		t.Fatalf("first certificate: %v", err)
	}
	corrupt := projectorEvent(t, projections.EventCertificateRecorded, projections.CertificateRecorded{
		ID: certID, Subject: "CN=different.example", Fingerprint: "sha256:different", Serial: "99",
	})
	corrupt, err = log.Append(ctx, corrupt)
	if err != nil {
		t.Fatal(err)
	}
	err = proj.Apply(ctx, corrupt)
	if err == nil || !strings.Contains(err.Error(), "reuses id") || strings.Contains(err.Error(), "certificates_pkey") {
		t.Fatalf("corrupt certificate id reuse error = %v, want stable domain error without raw SQL constraint", err)
	}
}

// TestConnectorReceiptProjectionConvergesByOutbox pins the second natural key
// on connector evidence. A retry may carry a fresh receipt UUID, but one outbox
// command still has one canonical receipt whose latest status wins.
func TestConnectorReceiptProjectionConvergesByOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	proj := projections.New(s)
	outboxID := int64(42)
	for _, candidate := range []projections.ConnectorDeliveryRecorded{
		{ID: "10000000-0000-4000-8000-000000000096", OutboxID: &outboxID, Destination: "connector.deploy", Connector: "nginx", Target: "edge", Status: "failed", Attempts: 1},
		{ID: "10000000-0000-4000-8000-000000000097", OutboxID: &outboxID, Destination: "connector.deploy", Connector: "nginx", Target: "edge", Status: "delivered", Attempts: 2},
	} {
		if err := proj.Apply(ctx, projectorEvent(t, projections.EventConnectorDeliveryRecorded, candidate)); err != nil {
			t.Fatalf("apply connector receipt %s: %v", candidate.Status, err)
		}
	}
	receipts, err := s.ListConnectorDeliveryReceiptsPage(ctx, tenantA, "", store.ZeroUUID, 10)
	if err != nil {
		t.Fatalf("list connector receipts: %v", err)
	}
	if len(receipts) != 1 || receipts[0].Status != "delivered" || receipts[0].Attempts != 2 {
		t.Fatalf("connector receipts = %+v, want one converged delivered receipt", receipts)
	}
}

// TestRotationRunProjectionConvergesWithInlineTailRace reproduces AUD-103's
// double-writer order. The inline projector has already inserted terminal
// evidence with one payload ID but has not committed; the durable tail then
// reaches the older running event, whose different payload ID names the same
// tenant/outbox operation. PostgreSQL must serialize the writers and the sink
// must converge on one terminal row instead of surfacing the outbox uniqueness
// constraint or letting the stale running event win.
func TestRotationRunProjectionConvergesWithInlineTailRace(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	const (
		runningID  = "10000000-0000-4000-8000-000000000090"
		terminalID = "10000000-0000-4000-8000-000000000091"
		identityID = "10000000-0000-4000-8000-000000000092"
	)
	outboxID := int64(84)
	runningAt := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	completedAt := runningAt.Add(time.Second)
	runningEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, projections.LifecycleRotationRecorded{
		ID: runningID, IdentityID: identityID, OutboxID: &outboxID, Status: "running",
		Trigger: "scheduled", Reason: "renewal window", PredecessorFingerprint: "sha256:old",
		IdempotencyKey: "lifecycle.renew:race",
	})
	runningEvent.Sequence = 329
	runningEvent.Time = runningAt
	terminal := store.RotationRun{
		ID: terminalID, TenantID: tenantA, IdentityID: identityID, OutboxID: &outboxID,
		Status: "succeeded", Trigger: "scheduled", Reason: "renewal window",
		PredecessorFingerprint: "sha256:old", SuccessorFingerprint: "sha256:new",
		RollbackRef: "restore sha256:old", IdempotencyKey: "lifecycle.renew:race",
		CreatedAt: completedAt, UpdatedAt: completedAt, CompletedAt: &completedAt,
		FirstEventSequence: 333, LatestEventSequence: 333,
	}

	rowInserted := make(chan struct{})
	releaseCommit := make(chan struct{})
	inlineDone := make(chan error, 1)
	go func() {
		inlineDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if err := s.ApplyRotationRunRecordedTx(ctx, tx, terminal); err != nil {
				return err
			}
			close(rowInserted)
			<-releaseCommit
			return nil
		})
	}()
	select {
	case <-rowInserted:
	case err := <-inlineDone:
		t.Fatalf("inline terminal projection insert: %v", err)
	}

	tailDone := make(chan error, 1)
	go func() { tailDone <- projections.New(s).Apply(ctx, runningEvent) }()
	select {
	case err := <-tailDone:
		close(releaseCommit)
		t.Fatalf("tail projection returned before the inline uniqueness lock committed: %v", err)
	case <-time.After(100 * time.Millisecond):
		// The older tail transaction is waiting on the inline outbox identity.
	}
	close(releaseCommit)
	if err := <-inlineDone; err != nil {
		t.Fatalf("inline terminal projection commit: %v", err)
	}
	if err := <-tailDone; err != nil {
		t.Fatalf("tail running projection after inline commit: %v", err)
	}

	runs, err := s.ListRotationRunsPage(ctx, tenantA, "", store.ZeroUUID, 10)
	if err != nil {
		t.Fatalf("list rotation runs: %v", err)
	}
	if len(runs) != 1 || runs[0].ID != runningID || runs[0].Status != "succeeded" || runs[0].OutboxID == nil ||
		*runs[0].OutboxID != outboxID || runs[0].SuccessorFingerprint != "sha256:new" ||
		!runs[0].CreatedAt.Equal(runningAt) || !runs[0].UpdatedAt.Equal(completedAt) ||
		runs[0].CompletedAt == nil || !runs[0].CompletedAt.Equal(completedAt) ||
		runs[0].FirstEventSequence != runningEvent.Sequence || runs[0].LatestEventSequence != terminal.LatestEventSequence {
		t.Fatalf("racing rotation projections = %+v, want one converged terminal run", runs)
	}
}

// TestRotationRunProjectionConvergesByOutbox pins the tenant/outbox natural
// identity independently of the payload row ID. A worker may emit a fresh UUID
// for the terminal observation, but it still describes one tenant-local outbox
// operation. The same numeric outbox ID in another tenant remains a separate
// run under RLS.
func TestRotationRunProjectionConvergesByOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenant := range []struct{ id, name string }{{tenantA, "Acme"}, {tenantB, "Beta"}} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant.id, Name: tenant.name}); err != nil {
			t.Fatalf("seed tenant %s: %v", tenant.id, err)
		}
	}
	proj := projections.New(s)
	outboxID := int64(85)
	baseTime := time.Date(2026, 8, 10, 12, 5, 0, 0, time.UTC)
	completedAt := baseTime.Add(time.Second)
	running := projections.LifecycleRotationRecorded{
		ID:         "10000000-0000-4000-8000-000000000093",
		IdentityID: "10000000-0000-4000-8000-000000000094", OutboxID: &outboxID,
		Status: "running", Trigger: "scheduled", Reason: "renewal window",
		PredecessorFingerprint: "sha256:a-old", IdempotencyKey: "lifecycle.renew:a",
	}
	runningEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, running)
	runningEvent.Sequence = 1
	runningEvent.Time = baseTime
	if err := proj.Apply(ctx, runningEvent); err != nil {
		t.Fatalf("apply tenant A running event: %v", err)
	}
	if err := proj.Apply(ctx, runningEvent); err != nil {
		t.Fatalf("replay exact tenant A running event: %v", err)
	}

	succeeded := running
	succeeded.ID = "10000000-0000-4000-8000-000000000095"
	succeeded.Status = "succeeded"
	succeeded.SuccessorFingerprint = "sha256:a-new"
	succeeded.RollbackRef = "restore sha256:a-old"
	succeeded.CompletedAt = &completedAt
	succeededEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, succeeded)
	succeededEvent.Sequence = 2
	succeededEvent.Time = completedAt
	if err := proj.Apply(ctx, succeededEvent); err != nil {
		t.Fatalf("apply tenant A terminal event through outbox identity: %v", err)
	}
	if err := proj.Apply(ctx, succeededEvent); err != nil {
		t.Fatalf("replay exact tenant A terminal event: %v", err)
	}

	tenantBEvent := projectorEventForTenant(t, tenantB, projections.EventLifecycleRotationRecorded, projections.LifecycleRotationRecorded{
		ID:         "20000000-0000-4000-8000-000000000093",
		IdentityID: "20000000-0000-4000-8000-000000000094", OutboxID: &outboxID,
		Status: "running", Trigger: "manual", Reason: "operator request",
		PredecessorFingerprint: "sha256:b-old", IdempotencyKey: "lifecycle.renew:b",
	})
	tenantBEvent.Sequence = 3
	tenantBEvent.Time = baseTime
	if err := proj.Apply(ctx, tenantBEvent); err != nil {
		t.Fatalf("apply tenant B event sharing numeric outbox id: %v", err)
	}

	runsA, err := s.ListRotationRunsPage(ctx, tenantA, "", store.ZeroUUID, 10)
	if err != nil {
		t.Fatalf("list tenant A rotation runs: %v", err)
	}
	runsB, err := s.ListRotationRunsPage(ctx, tenantB, "", store.ZeroUUID, 10)
	if err != nil {
		t.Fatalf("list tenant B rotation runs: %v", err)
	}
	if len(runsA) != 1 || runsA[0].Status != "succeeded" || runsA[0].ID != running.ID ||
		runsA[0].SuccessorFingerprint != succeeded.SuccessorFingerprint {
		t.Fatalf("tenant A rotation runs = %+v, want one outbox-converged terminal row", runsA)
	}
	if len(runsB) != 1 || runsB[0].Status != "running" || runsB[0].IdentityID == runsA[0].IdentityID {
		t.Fatalf("tenant B rotation runs = %+v, want its independent running row", runsB)
	}
}

// TestRotationRunProjectionReplaysV05MissingPredecessor proves an upgrade from
// v0.5.x can rebuild ordered projection state without discarding the public
// predecessor binding retained by the legacy row. Only rows marked by migration
// 0194 get this compatibility treatment; a non-empty mismatch still fails.
func TestRotationRunProjectionReplaysV05MissingPredecessor(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	const (
		runID      = "10000000-0000-4000-8000-000000000194"
		identityID = "10000000-0000-4000-8000-000000000195"
	)
	outboxID := int64(194)
	runningAt := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	completedAt := runningAt.Add(time.Second)
	legacyCompletedAt := completedAt
	legacy := store.RotationRun{
		ID: runID, TenantID: tenantA, IdentityID: identityID, OutboxID: &outboxID,
		Status: "succeeded", Trigger: "scheduled", Reason: "renewal window",
		PredecessorFingerprint: "sha256:v05-old", SuccessorFingerprint: "sha256:v05-new",
		RollbackRef: "restore sha256:v05-old", IdempotencyKey: "lifecycle.renew:v05",
		CreatedAt: runningAt, UpdatedAt: completedAt, CompletedAt: &legacyCompletedAt,
		LegacyPredecessorBinding: true,
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyRotationRunRecordedTx(ctx, tx, legacy)
	}); err != nil {
		t.Fatalf("seed pre-0194 projected row: %v", err)
	}

	projector := projections.New(s)
	running := projections.LifecycleRotationRecorded{
		ID: runID, IdentityID: identityID, OutboxID: &outboxID, Status: "running",
		Trigger: "scheduled", Reason: "renewal window", IdempotencyKey: "lifecycle.renew:v05",
	}
	runningEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, running)
	runningEvent.Sequence = 180
	runningEvent.Time = runningAt
	if err := projector.Apply(ctx, runningEvent); err != nil {
		t.Fatalf("replay v0.5 running event with omitted predecessor: %v", err)
	}

	terminal := running
	terminal.Status = "succeeded"
	terminal.SuccessorFingerprint = "sha256:v05-new"
	terminal.RollbackRef = "restore sha256:v05-old"
	terminal.CompletedAt = &completedAt
	terminalEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, terminal)
	terminalEvent.Sequence = 181
	terminalEvent.Time = completedAt
	if err := projector.Apply(ctx, terminalEvent); err != nil {
		t.Fatalf("replay v0.5 terminal event with omitted predecessor: %v", err)
	}

	got, err := s.GetRotationRun(ctx, tenantA, runID)
	if err != nil {
		t.Fatalf("get replayed v0.5 rotation run: %v", err)
	}
	if got.Status != "succeeded" || got.PredecessorFingerprint != legacy.PredecessorFingerprint ||
		got.SuccessorFingerprint != terminal.SuccessorFingerprint || got.FirstEventSequence != 180 ||
		got.LatestEventSequence != 181 || !got.LegacyPredecessorBinding {
		t.Fatalf("replayed v0.5 rotation run = %+v, want retained binding and ordered terminal state", got)
	}

	changed := terminal
	changed.PredecessorFingerprint = "sha256:different-old"
	changedEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, changed)
	changedEvent.Sequence = 182
	changedEvent.Time = completedAt.Add(time.Second)
	if err := projector.Apply(ctx, changedEvent); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("non-empty predecessor drift error = %v, want ErrIdempotencyConflict", err)
	}
}

// TestRotationRunProjectionRejectsBindingDrift proves that convergence is not
// a last-writer-wins rewrite. Either uniqueness boundary may locate the row,
// but a changed command binding or a changed same-state observation must fail
// with the repository's stable idempotency-domain error.
func TestRotationRunProjectionRejectsBindingDrift(t *testing.T) {
	outboxID := int64(86)
	otherOutboxID := int64(87)
	completedAt := time.Date(2026, 8, 10, 12, 10, 1, 0, time.UTC)
	base := projections.LifecycleRotationRecorded{
		ID:         "10000000-0000-4000-8000-000000000096",
		IdentityID: "10000000-0000-4000-8000-000000000097", OutboxID: &outboxID,
		Status: "running", Trigger: "scheduled", Reason: "renewal window",
		PredecessorFingerprint: "sha256:binding-old", IdempotencyKey: "lifecycle.renew:binding",
	}
	tests := []struct {
		name   string
		mutate func(*projections.LifecycleRotationRecorded)
	}{
		{name: "same row id changes outbox", mutate: func(candidate *projections.LifecycleRotationRecorded) {
			candidate.OutboxID = &otherOutboxID
		}},
		{name: "same outbox changes identity", mutate: func(candidate *projections.LifecycleRotationRecorded) {
			candidate.ID = "10000000-0000-4000-8000-000000000098"
			candidate.IdentityID = "10000000-0000-4000-8000-000000000099"
		}},
		{name: "same outbox changes trigger", mutate: func(candidate *projections.LifecycleRotationRecorded) {
			candidate.ID = "10000000-0000-4000-8000-000000000098"
			candidate.Trigger = "manual"
		}},
		{name: "same outbox changes reason", mutate: func(candidate *projections.LifecycleRotationRecorded) {
			candidate.ID = "10000000-0000-4000-8000-000000000098"
			candidate.Reason = "changed reason"
		}},
		{name: "same outbox changes predecessor", mutate: func(candidate *projections.LifecycleRotationRecorded) {
			candidate.ID = "10000000-0000-4000-8000-000000000098"
			candidate.PredecessorFingerprint = "sha256:different-old"
		}},
		{name: "same outbox changes idempotency key", mutate: func(candidate *projections.LifecycleRotationRecorded) {
			candidate.ID = "10000000-0000-4000-8000-000000000098"
			candidate.IdempotencyKey = "lifecycle.renew:different"
		}},
		{name: "same running state changes outcome fields", mutate: func(candidate *projections.LifecycleRotationRecorded) {
			candidate.ID = "10000000-0000-4000-8000-000000000098"
			candidate.SuccessorFingerprint = "sha256:impossible-running-successor"
			candidate.CompletedAt = &completedAt
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
				t.Fatalf("seed tenant: %v", err)
			}
			proj := projections.New(s)
			first := projectorEvent(t, projections.EventLifecycleRotationRecorded, base)
			first.Sequence = 10
			first.Time = time.Date(2026, 8, 10, 12, 10, 0, 0, time.UTC)
			if err := proj.Apply(ctx, first); err != nil {
				t.Fatalf("apply original rotation run: %v", err)
			}

			candidate := base
			test.mutate(&candidate)
			candidateEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, candidate)
			candidateEvent.Sequence = first.Sequence
			candidateEvent.Time = first.Time
			err := proj.Apply(ctx, candidateEvent)
			if !errors.Is(err, store.ErrIdempotencyConflict) {
				t.Fatalf("binding drift error = %v, want ErrIdempotencyConflict", err)
			}
		})
	}
}

// TestRotationRunProjectionDoesNotRegressTerminalState proves that a delayed
// tail replay cannot erase either successful or failed terminal evidence. The
// binding is still validated, but an older running snapshot becomes a no-op.
func TestRotationRunProjectionDoesNotRegressTerminalState(t *testing.T) {
	for _, terminalStatus := range []string{"succeeded", "failed"} {
		t.Run(terminalStatus, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
				t.Fatalf("seed tenant: %v", err)
			}
			proj := projections.New(s)
			outboxID := int64(88)
			runningAt := time.Date(2026, 8, 10, 12, 15, 0, 0, time.UTC)
			completedAt := runningAt.Add(time.Second)
			terminal := projections.LifecycleRotationRecorded{
				ID:         "10000000-0000-4000-8000-000000000100",
				IdentityID: "10000000-0000-4000-8000-000000000101", OutboxID: &outboxID,
				Status: terminalStatus, Trigger: "scheduled", Reason: "renewal window",
				PredecessorFingerprint: "sha256:terminal-old", IdempotencyKey: "lifecycle.renew:terminal",
				CompletedAt: &completedAt,
			}
			if terminalStatus == "succeeded" {
				terminal.SuccessorFingerprint = "sha256:terminal-new"
				terminal.RollbackRef = "restore sha256:terminal-old"
			} else {
				terminal.Error = "connector exhausted retries"
			}
			terminalEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, terminal)
			terminalEvent.Sequence = 20
			terminalEvent.Time = completedAt
			if err := proj.Apply(ctx, terminalEvent); err != nil {
				t.Fatalf("apply terminal rotation event: %v", err)
			}

			stale := terminal
			stale.Status = "running"
			stale.SuccessorFingerprint = ""
			stale.RollbackRef = ""
			stale.Error = ""
			stale.CompletedAt = nil
			staleEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, stale)
			staleEvent.Sequence = 19
			staleEvent.Time = runningAt
			if err := proj.Apply(ctx, staleEvent); err != nil {
				t.Fatalf("apply stale running replay: %v", err)
			}

			got, err := s.GetRotationRun(ctx, tenantA, terminal.ID)
			if err != nil {
				t.Fatalf("get terminal rotation run: %v", err)
			}
			if got.Status != terminalStatus || got.SuccessorFingerprint != terminal.SuccessorFingerprint ||
				got.RollbackRef != terminal.RollbackRef || got.Error != terminal.Error ||
				got.CompletedAt == nil || !got.CompletedAt.Equal(completedAt) || !got.UpdatedAt.Equal(completedAt) {
				t.Fatalf("terminal rotation after stale replay = %+v, want unchanged %s evidence", got, terminalStatus)
			}

			// A failed delivery is recorded on every attempt, while the outbox is
			// allowed to retry. Only an older running event is stale: a newer retry
			// must reopen failed evidence so a later success can replace it.
			if terminalStatus == "failed" {
				retryAt := completedAt.Add(time.Second)
				retryEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, stale)
				retryEvent.Sequence = 21
				retryEvent.Time = retryAt
				if err := proj.Apply(ctx, retryEvent); err != nil {
					t.Fatalf("apply newer running retry: %v", err)
				}
				retrying, err := s.GetRotationRun(ctx, tenantA, terminal.ID)
				if err != nil {
					t.Fatalf("get retried rotation run: %v", err)
				}
				if retrying.Status != "running" || retrying.Error != "" || retrying.CompletedAt != nil ||
					!retrying.UpdatedAt.Equal(retryAt) {
					t.Fatalf("newer retry did not reopen failed run: %+v", retrying)
				}
			}
		})
	}
}

// TestRotationRunProjectionReplaysPostgreSQLNormalizedCompletionAUD126 pins
// the storage precision boundary on exact at-least-once replay. Event JSON can
// retain nanoseconds, while PostgreSQL timestamptz stores microseconds. Those two
// encodings still describe the same immutable completion observation.
func TestRotationRunProjectionReplaysPostgreSQLNormalizedCompletionAUD126(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	outboxID := int64(126)
	completedAt := time.Date(2026, 8, 13, 21, 11, 9, 534027882, time.UTC)
	recorded := projections.LifecycleRotationRecorded{
		ID:         "10000000-0000-4000-8000-000000000126",
		IdentityID: "10000000-0000-4000-8000-000000000127", OutboxID: &outboxID,
		Status: "succeeded", Trigger: "scheduled", Reason: "renewal window",
		PredecessorFingerprint: "sha256:precision-old", SuccessorFingerprint: "sha256:precision-new",
		RollbackRef: "restore sha256:precision-old", IdempotencyKey: "lifecycle.renew:precision",
		CompletedAt: &completedAt,
	}
	event := projectorEvent(t, projections.EventLifecycleRotationRecorded, recorded)
	event.Sequence = 126
	event.Time = time.Date(2026, 8, 13, 21, 11, 9, 670315632, time.UTC)
	proj := projections.New(s)
	if err := proj.Apply(ctx, event); err != nil {
		t.Fatalf("first terminal projection: %v", err)
	}
	if err := proj.Apply(ctx, event); err != nil {
		t.Fatalf("identical same-sequence replay after PostgreSQL timestamp encoding: %v", err)
	}

	got, err := s.GetRotationRun(ctx, tenantA, recorded.ID)
	if err != nil {
		t.Fatalf("get replayed rotation run: %v", err)
	}
	if got.LatestEventSequence != event.Sequence || got.CompletedAt == nil || !got.CompletedAt.Equal(completedAt.Truncate(time.Microsecond)) {
		t.Fatalf("replayed rotation run = %+v, want sequence %d and PostgreSQL-normalized completion %s", got, event.Sequence, completedAt.Truncate(time.Microsecond))
	}

	changedAt := completedAt.Add(time.Microsecond)
	changed := recorded
	changed.CompletedAt = &changedAt
	changedEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, changed)
	changedEvent.ID = event.ID
	changedEvent.Sequence = event.Sequence
	changedEvent.Time = event.Time
	if err := proj.Apply(ctx, changedEvent); !errors.Is(err, store.ErrIdempotencyConflict) || !strings.Contains(err.Error(), "differing_same_sequence_fields=completed_at") {
		t.Fatalf("same-sequence retained-microsecond change error = %v, want completed_at idempotency conflict", err)
	}
}

// TestRotationRunProjectionOrdersByLocalStreamSequence proves the immutable
// local JetStream order, not a producer/import wall clock, decides which
// lifecycle observation is current. Federation preserves source timestamps and
// clocks can step backwards, while the local sequence is always monotonic.
func TestRotationRunProjectionOrdersByLocalStreamSequence(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	proj := projections.New(s)
	outboxID := int64(89)
	identityID := "10000000-0000-4000-8000-000000000102"
	runID := "10000000-0000-4000-8000-000000000103"
	lateClock := time.Date(2026, 8, 10, 14, 0, 0, 0, time.UTC)
	earlyClock := lateClock.Add(-time.Hour)

	running := projections.LifecycleRotationRecorded{
		ID: runID, IdentityID: identityID, OutboxID: &outboxID, Status: "running",
		Trigger: "scheduled", Reason: "renewal window",
		PredecessorFingerprint: "sha256:sequence-old", IdempotencyKey: "lifecycle.renew:sequence",
	}
	runningEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, running)
	runningEvent.Sequence = 100
	runningEvent.Time = lateClock
	if err := proj.Apply(ctx, runningEvent); err != nil {
		t.Fatalf("apply running event: %v", err)
	}

	completedAt := earlyClock
	succeeded := running
	succeeded.Status = "succeeded"
	succeeded.SuccessorFingerprint = "sha256:sequence-new"
	succeeded.RollbackRef = "restore sha256:sequence-old"
	succeeded.CompletedAt = &completedAt
	succeededEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, succeeded)
	succeededEvent.Sequence = 101
	succeededEvent.Time = earlyClock // later stream event, deliberately older wall clock
	if err := proj.Apply(ctx, succeededEvent); err != nil {
		t.Fatalf("apply later-sequence success with older clock: %v", err)
	}

	got, err := s.GetRotationRun(ctx, tenantA, runID)
	if err != nil {
		t.Fatalf("get sequence-ordered run: %v", err)
	}
	if got.Status != "succeeded" || got.SuccessorFingerprint != succeeded.SuccessorFingerprint ||
		got.CompletedAt == nil || !got.CompletedAt.Equal(completedAt) {
		t.Fatalf("sequence-ordered rotation = %+v, want later-sequence success", got)
	}
}

// TestRotationRunProjectionSucceededCannotReopen proves a later event cannot
// turn a completed external effect back into running authority. Failed attempts
// may retry; succeeded evidence is final for its immutable outbox binding.
func TestRotationRunProjectionSucceededCannotReopen(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	proj := projections.New(s)
	outboxID := int64(90)
	completedAt := time.Date(2026, 8, 10, 15, 0, 0, 0, time.UTC)
	terminal := projections.LifecycleRotationRecorded{
		ID:         "10000000-0000-4000-8000-000000000104",
		IdentityID: "10000000-0000-4000-8000-000000000105", OutboxID: &outboxID,
		Status: "succeeded", Trigger: "scheduled", Reason: "renewal window",
		PredecessorFingerprint: "sha256:final-old", SuccessorFingerprint: "sha256:final-new",
		RollbackRef: "restore sha256:final-old", IdempotencyKey: "lifecycle.renew:final",
		CompletedAt: &completedAt,
	}
	terminalEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, terminal)
	terminalEvent.Sequence = 200
	terminalEvent.Time = completedAt
	if err := proj.Apply(ctx, terminalEvent); err != nil {
		t.Fatalf("apply succeeded event: %v", err)
	}

	reopened := terminal
	reopened.Status = "running"
	reopened.SuccessorFingerprint = ""
	reopened.RollbackRef = ""
	reopened.CompletedAt = nil
	reopenedEvent := projectorEvent(t, projections.EventLifecycleRotationRecorded, reopened)
	reopenedEvent.Sequence = 201
	reopenedEvent.Time = completedAt.Add(time.Second)
	if err := proj.Apply(ctx, reopenedEvent); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("later running after success error = %v, want ErrIdempotencyConflict", err)
	}
}

// TestCertificateProjectionConvergesWithInlineTailRace reproduces the served
// at-least-once race: the event is visible in JetStream while the inline SQL
// projection is still committing, so the durable tail can try the same insert
// concurrently. Either writer may discover the id or fingerprint uniqueness
// conflict first; both must converge to the same one-row inventory.
func TestCertificateProjectionConvergesWithInlineTailRace(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	const certID = "10000000-0000-4000-8000-000000000099"
	event := projectorEvent(t, projections.EventCertificateRecorded, projections.CertificateRecorded{
		ID: certID, Subject: "CN=race.example", SANs: []string{"race.example"},
		Fingerprint: "sha256:projection-race", Serial: "99", Source: "issued",
	})
	log := openLog(t)
	event, err := log.Append(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	projector := projections.New(s)

	rowInserted := make(chan struct{})
	releaseCommit := make(chan struct{})
	inlineDone := make(chan error, 1)
	go func() {
		inlineDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if err := projector.ApplyTx(ctx, tx, event); err != nil {
				return err
			}
			close(rowInserted)
			<-releaseCommit
			return nil
		})
	}()
	select {
	case <-rowInserted:
	case err := <-inlineDone:
		t.Fatalf("inline projection insert: %v", err)
	}

	tailDone := make(chan error, 1)
	go func() { tailDone <- projector.Apply(ctx, event) }()
	select {
	case err := <-tailDone:
		close(releaseCommit)
		t.Fatalf("tail projection returned before the inline metadata transaction committed: %v", err)
	case <-time.After(100 * time.Millisecond):
		// The second transaction is waiting on the first transaction's uncommitted event receipt.
	}
	close(releaseCommit)
	if err := <-inlineDone; err != nil {
		t.Fatalf("inline projection commit: %v", err)
	}
	if err := <-tailDone; err != nil {
		t.Fatalf("tail projection after inline commit: %v", err)
	}

	items, err := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, nil, 10, nil)
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	if len(items) != 1 || items[0].ID != certID || items[0].Fingerprint != "sha256:projection-race" {
		t.Fatalf("racing projections = %+v, want one canonical certificate", items)
	}
}

// TestProjectorCreateEventsAreReplayIdempotentWithTenantCompositeKeys pins the
// live-writer contract used by the API's inline projector and the durable tailer:
// applying the same source event again must converge to one read-model row, not
// surface a duplicate-key error on the tenant-composite key (tenant_id, id).
func TestProjectorCreateEventsAreReplayIdempotentWithTenantCompositeKeys(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	proj := projections.New(s)

	const (
		ownerID  = "10000000-0000-4000-8000-000000000001"
		issuerID = "10000000-0000-4000-8000-000000000002"
		identID  = "10000000-0000-4000-8000-000000000003"
	)
	issuerPtr := issuerID
	eventsToReplay := []events.Event{
		projectorEvent(t, projections.EventOwnerCreated, projections.OwnerCreated{
			ID: ownerID, Kind: "workload", Name: "payments",
		}),
		projectorEvent(t, projections.EventIssuerCreated, projections.IssuerCreated{
			ID: issuerID, Kind: "x509_ca", Name: "e2e-ca",
			Chain: []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"},
		}),
		projectorEvent(t, projections.EventIdentityCreated, projections.IdentityCreated{
			ID: identID, Kind: "x509_certificate", Name: "payments.example",
			OwnerID: ownerID, IssuerID: &issuerPtr, Attributes: json.RawMessage(`{}`),
		}),
	}

	for _, ev := range eventsToReplay {
		if err := proj.Apply(ctx, ev); err != nil {
			t.Fatalf("first apply %s: %v", ev.Type, err)
		}
		if err := proj.Apply(ctx, ev); err != nil {
			t.Fatalf("replay apply %s: %v", ev.Type, err)
		}
	}

	owners, err := s.ListOwners(ctx, tenantA)
	if err != nil {
		t.Fatalf("list owners: %v", err)
	}
	issuers, err := s.ListIssuers(ctx, tenantA)
	if err != nil {
		t.Fatalf("list issuers: %v", err)
	}
	identities, err := s.ListIdentities(ctx, tenantA)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(owners) != 1 || len(issuers) != 1 || len(identities) != 1 {
		t.Fatalf("replayed read model counts = owners:%d issuers:%d identities:%d, want 1/1/1",
			len(owners), len(issuers), len(identities))
	}
}

// TestCORRECT003CreateProjectionIDsAreTenantScoped proves the schema matches the
// projector's tenant-composite conflict target. The read-model identity is
// (tenant_id, id); a single-column id primary key makes the second tenant fail
// with owners_pkey before compose can prove the served lifecycle.
func TestCORRECT003CreateProjectionIDsAreTenantScoped(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenant := range []struct{ id, name string }{{tenantA, "Acme"}, {tenantB, "Beta"}} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant.id, Name: tenant.name}); err != nil {
			t.Fatalf("seed tenant %s: %v", tenant.id, err)
		}
	}
	proj := projections.New(s)

	const (
		ownerID  = "10000000-0000-4000-8000-000000000201"
		issuerID = "10000000-0000-4000-8000-000000000202"
		identID  = "10000000-0000-4000-8000-000000000203"
	)
	issuerPtr := issuerID
	for _, tenantID := range []string{tenantA, tenantB} {
		if err := proj.Apply(ctx, projectorEventForTenant(t, tenantID, projections.EventOwnerCreated, projections.OwnerCreated{
			ID: ownerID, Kind: "workload", Name: "shared-id-owner",
		})); err != nil {
			t.Fatalf("apply owner.created for tenant %s: %v", tenantID, err)
		}
		if err := proj.Apply(ctx, projectorEventForTenant(t, tenantID, projections.EventIssuerCreated, projections.IssuerCreated{
			ID: issuerID, Kind: "x509_ca", Name: "shared-id-ca",
			Chain: []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"},
		})); err != nil {
			t.Fatalf("apply issuer.created for tenant %s: %v", tenantID, err)
		}
		if err := proj.Apply(ctx, projectorEventForTenant(t, tenantID, projections.EventIdentityCreated, projections.IdentityCreated{
			ID: identID, Kind: "x509_certificate", Name: "shared-id.example",
			OwnerID: ownerID, IssuerID: &issuerPtr, Attributes: json.RawMessage(`{}`),
		})); err != nil {
			t.Fatalf("apply identity.created for tenant %s: %v", tenantID, err)
		}
	}

	for _, tenantID := range []string{tenantA, tenantB} {
		owners, err := s.ListOwners(ctx, tenantID)
		if err != nil {
			t.Fatalf("list owners for tenant %s: %v", tenantID, err)
		}
		issuers, err := s.ListIssuers(ctx, tenantID)
		if err != nil {
			t.Fatalf("list issuers for tenant %s: %v", tenantID, err)
		}
		identities, err := s.ListIdentities(ctx, tenantID)
		if err != nil {
			t.Fatalf("list identities for tenant %s: %v", tenantID, err)
		}
		if len(owners) != 1 || len(issuers) != 1 || len(identities) != 1 {
			t.Fatalf("tenant %s read model counts = owners:%d issuers:%d identities:%d, want 1/1/1",
				tenantID, len(owners), len(issuers), len(identities))
		}
	}
}

func projectorEvent(t *testing.T, eventType string, payload any) events.Event {
	return projectorEventForTenant(t, tenantA, eventType, payload)
}

func projectorEventForTenant(t *testing.T, tenantID, eventType string, payload any) events.Event {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s: %v", eventType, err)
	}
	return events.Event{Type: eventType, TenantID: tenantID, Time: time.Now().UTC(), Data: data}
}
