// SPDX-License-Identifier: BUSL-1.1

// Package rewrap implements PCAS-claim-15's "re-wrap before retirement" as durable
// orchestration (PCAS-claim-39; establishes the re-wrap limb of INV-15). Data protected
// under a predecessor KEM key is re-wrapped under the successor by staged, resumable
// jobs DERIVED FROM the succession record: bounded stages with per-stage health
// verification, resumable after a crash (idempotent stages, AN-5), with stage and
// completion events recorded on the AN-2 ledger and published through the outbox
// (AN-6, via the PCAS-08 seams). A KEM predecessor's retirement condition then
// REQUIRES the recorded re-wrap completion events (in addition to PCAS-10's ack
// quorum), so retirement can never precede completion. The envelope/transit
// re-encryption primitives themselves are core (internal/transit); this package is
// the orchestration + the gate.
package rewrap

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/succession"
)

// Errors.
var (
	ErrStageHealth      = errors.New("rewrap: stage health verification failed")
	ErrRewrapIncomplete = errors.New("rewrap: re-wrap is not complete; predecessor retirement is blocked")
)

// Job is a staged re-wrap derived from a succession record: the identity, the
// predecessor/successor KEM epochs and algorithms, and the scope of protected data
// expressed as bounded Stages (e.g. data-item or batch ids).
type Job struct {
	IdentityID        string
	TenantID          string
	PredecessorEpoch  uint64
	SuccessorEpoch    uint64
	PredecessorKEMAlg string
	SuccessorKEMAlg   string
	Stages            []string
}

// ID is the deterministic job identifier derived from the succession it re-wraps.
func (j Job) ID() string {
	return fmt.Sprintf("rewrap:%s:%d->%d", j.IdentityID, j.PredecessorEpoch, j.SuccessorEpoch)
}

// JobFromRecord derives a re-wrap job from a succession record and the data scope
// (the stage ids). The predecessor/successor algorithms and epochs come from the
// record, so the job is bound to the succession that occasioned it.
func JobFromRecord(rec succession.SuccessionRecord, stages []string) Job {
	return Job{
		IdentityID:        rec.Fields.IdentityID,
		TenantID:          rec.Fields.TenantID,
		PredecessorEpoch:  rec.Fields.PredecessorEpoch,
		SuccessorEpoch:    rec.Fields.Epoch,
		PredecessorKEMAlg: string(rec.Fields.PredecessorAlg),
		SuccessorKEMAlg:   string(rec.Fields.SuccessorAlg),
		Stages:            append([]string(nil), stages...),
	}
}

// ProgressStore is the resumable, idempotent record of completed stages (AN-5). In
// production it is the core store; a MemProgress is provided for tests / single node.
type ProgressStore interface {
	Completed(jobID string) (map[string]bool, error)
	Mark(jobID, stageID string) error
}

// EventAppender is the AN-2 ledger sink. *events.Log and the rewrap.Ledger satisfy it.
type EventAppender interface {
	Append(ctx context.Context, e events.Event) (events.Event, error)
}

// StageFunc performs the re-wrap for one stage (the transit primitive is core).
type StageFunc func(ctx context.Context, stageID string) error

// HealthFunc verifies a stage's health after it runs; a non-nil error halts the job.
type HealthFunc func(ctx context.Context, stageID string) error

// Result summarizes a run.
type Result struct {
	StagesRun     int
	StagesSkipped int
	Completed     bool
}

// Runner runs re-wrap jobs, resumable and idempotent, recording stage + completion
// events on the ledger.
type Runner struct {
	progress ProgressStore
	ledger   EventAppender
}

// NewRunner builds a Runner over a progress store and the AN-2 ledger.
func NewRunner(progress ProgressStore, ledger EventAppender) *Runner {
	return &Runner{progress: progress, ledger: ledger}
}

// Run executes the job's outstanding stages. A stage already marked complete is
// SKIPPED (resumable + idempotent: no double-wrap). Each executed stage is
// health-verified — a health failure halts progression with a structured error and
// records no completion. When every stage is complete, a completion event is
// recorded, which the retirement condition consumes.
func (r *Runner) Run(ctx context.Context, job Job, doStage StageFunc, health HealthFunc) (Result, error) {
	jobID := job.ID()
	done, err := r.progress.Completed(jobID)
	if err != nil {
		return Result{}, err
	}
	if done == nil {
		done = map[string]bool{}
	}
	var res Result
	for _, stage := range job.Stages {
		if done[stage] {
			res.StagesSkipped++
			continue
		}
		if err := doStage(ctx, stage); err != nil {
			return res, fmt.Errorf("rewrap: stage %q: %w", stage, err)
		}
		if err := health(ctx, stage); err != nil {
			return res, fmt.Errorf("%w: stage %q: %v", ErrStageHealth, stage, err)
		}
		if err := r.progress.Mark(jobID, stage); err != nil {
			return res, err
		}
		done[stage] = true
		if err := r.append(ctx, succession.RewrapStageV1{
			JobID: jobID, IdentityID: job.IdentityID, TenantID: job.TenantID,
			PredecessorEpoch: job.PredecessorEpoch, StageID: stage,
		}); err != nil {
			return res, err
		}
		res.StagesRun++
	}
	if len(done) >= len(job.Stages) && len(job.Stages) > 0 {
		if err := r.append(ctx, succession.RewrapCompletedV1{
			JobID: jobID, IdentityID: job.IdentityID, TenantID: job.TenantID,
			PredecessorEpoch: job.PredecessorEpoch, Stages: len(job.Stages),
		}); err != nil {
			return res, err
		}
		res.Completed = true
	}
	return res, nil
}

func (r *Runner) append(ctx context.Context, p succession.Payload) error {
	ev, err := succession.Encode(p)
	if err != nil {
		return err
	}
	_, err = r.ledger.Append(ctx, ev)
	return err
}

// MemProgress is an in-memory ProgressStore.
type MemProgress struct {
	mu sync.Mutex
	m  map[string]map[string]bool
}

// NewMemProgress builds an empty progress store.
func NewMemProgress() *MemProgress { return &MemProgress{m: map[string]map[string]bool{}} }

// Completed returns the completed-stage set for a job.
func (p *MemProgress) Completed(jobID string) (map[string]bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]bool{}
	for k, v := range p.m[jobID] {
		out[k] = v
	}
	return out, nil
}

// Mark records a stage complete (idempotent).
func (p *MemProgress) Mark(jobID, stageID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m[jobID] == nil {
		p.m[jobID] = map[string]bool{}
	}
	p.m[jobID][stageID] = true
	return nil
}

// Ledger is an in-memory AN-2 sink that also answers the re-wrap completion query for
// the retirement gate. Production reads the same completion events from the durable
// ledger / transparency log.
type Ledger struct {
	mu   sync.Mutex
	evs  []events.Event
	done map[string]bool // "identity@predEpoch" -> completed
}

// NewLedger builds an empty ledger.
func NewLedger() *Ledger { return &Ledger{done: map[string]bool{}} }

// Append records an event and tracks re-wrap completions.
func (l *Ledger) Append(_ context.Context, e events.Event) (events.Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Sequence = uint64(len(l.evs) + 1)
	l.evs = append(l.evs, e)
	if e.Type == succession.TypeRewrapCompleted {
		if p, err := succession.Decode(e); err == nil {
			if c, ok := p.(succession.RewrapCompletedV1); ok {
				l.done[completionKey(c.IdentityID, c.PredecessorEpoch)] = true
			}
		}
	}
	return e, nil
}

// IsComplete reports whether a re-wrap completion event was recorded for the
// predecessor at predecessorEpoch.
func (l *Ledger) IsComplete(identityID string, predecessorEpoch uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.done[completionKey(identityID, predecessorEpoch)]
}

func completionKey(identityID string, predecessorEpoch uint64) string {
	return fmt.Sprintf("%s@%d", identityID, predecessorEpoch)
}

// CompletionReporter reports whether re-wrap completed for a predecessor. *Ledger
// satisfies it; production is backed by the durable ledger.
type CompletionReporter interface {
	IsComplete(identityID string, predecessorEpoch uint64) bool
}

// RetirementGate returns a retirement PreRetire precondition that blocks predecessor
// retirement until the re-wrap completion events for (identityID, predecessorEpoch)
// are recorded (PCAS-claim-39). It is the standing INV-15 guard: whatever the mechanism,
// retirement cannot proceed while re-wrap is incomplete.
func RetirementGate(reporter CompletionReporter, identityID string, predecessorEpoch uint64) func(context.Context) error {
	return func(context.Context) error {
		if !reporter.IsComplete(identityID, predecessorEpoch) {
			return fmt.Errorf("%w: identity %q predecessor epoch %d", ErrRewrapIncomplete, identityID, predecessorEpoch)
		}
		return nil
	}
}
