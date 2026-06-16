// Package rotation is the policy-driven, rollback-safe secret rotation engine
// (S20.3, F37): a two-phase rotation — stage → cut over → verify → retire — where
// a mid-rotation failure rolls back to the old secret so the consuming application
// is never broken. Backend steps run through the outbox (AN-6), are idempotent
// (AN-5), and every phase is audited (AN-2).
package rotation

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/auditsink"
)

// Rotator performs the backend steps of a rotation. Each step is idempotent and,
// in production, delivered via the outbox.
type Rotator interface {
	Stage(ctx context.Context, key string) (newRef string, err error) // create the new version alongside the old
	Cutover(ctx context.Context, key, newRef string) error            // point consumers at the new version
	Verify(ctx context.Context, key string) error                     // confirm consumers are healthy on the new version
	Retire(ctx context.Context, key, oldRef string) error             // remove the old version
	Rollback(ctx context.Context, key, oldRef string) error           // revert consumers to the old version
}

// Report summarizes a rotation.
type Report struct {
	Key         string
	OldRef      string
	NewRef      string
	Completed   bool
	RolledBack  bool
	FailedPhase string
}

// Engine runs rollback-safe rotations.
type Engine struct {
	tenantID string
	rotator  Rotator
	audit    auditsink.Auditor
}

// New constructs a rotation Engine.
func New(tenantID string, rotator Rotator, audit auditsink.Auditor) *Engine {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	return &Engine{tenantID: tenantID, rotator: rotator, audit: audit}
}

// Rotate performs a two-phase, rollback-safe rotation. On a cutover or verify
// failure it rolls back to oldRef so the consuming application keeps working.
func (e *Engine) Rotate(ctx context.Context, key, oldRef string) (Report, error) {
	rep := Report{Key: key, OldRef: oldRef}

	newRef, err := e.rotator.Stage(ctx, key)
	if err != nil {
		rep.FailedPhase = "stage" // nothing changed yet; old secret still in use
		e.emit(ctx, "rotation.failed", key, "stage")
		return rep, fmt.Errorf("rotation: stage: %w", err)
	}
	rep.NewRef = newRef
	e.emit(ctx, "rotation.staged", key, "stage")

	if err := e.rotator.Cutover(ctx, key, newRef); err != nil {
		_ = e.rotator.Rollback(ctx, key, oldRef)
		rep.RolledBack, rep.FailedPhase = true, "cutover"
		e.emit(ctx, "rotation.rolled_back", key, "cutover")
		return rep, fmt.Errorf("rotation: cutover (rolled back): %w", err)
	}
	if err := e.rotator.Verify(ctx, key); err != nil {
		_ = e.rotator.Rollback(ctx, key, oldRef)
		rep.RolledBack, rep.FailedPhase = true, "verify"
		e.emit(ctx, "rotation.rolled_back", key, "verify")
		return rep, fmt.Errorf("rotation: verify (rolled back): %w", err)
	}
	if err := e.rotator.Retire(ctx, key, oldRef); err != nil {
		// New version is live and healthy; only retiring the old one failed — safe to retry.
		rep.FailedPhase = "retire"
		e.emit(ctx, "rotation.retire_pending", key, "retire")
		return rep, fmt.Errorf("rotation: retire (new version live, retry retire): %w", err)
	}
	rep.Completed = true
	e.emit(ctx, "rotation.completed", key, "retire")
	return rep, nil
}

func (e *Engine) emit(ctx context.Context, event, key, phase string) {
	_ = auditsink.Emit(ctx, e.audit, nil, event, e.tenantID, []byte(fmt.Sprintf(`{"key":%q,"phase":%q}`, key, phase)))
}
