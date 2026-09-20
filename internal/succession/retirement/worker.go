// SPDX-License-Identifier: BUSL-1.1

package retirement

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/events"
)

// Worker drives evidence-gated cutovers from the AN-2 ledger (INT-17): it extracts an
// identity's signed relying-party acknowledgements from ledger events, evaluates the
// quorum via the Controller, and — only if met — announces the pure-PQC succession,
// revokes then zeroizes the predecessor, and emits the retirement event binding the
// ack-set digest (PCAS-claims-2/3/8). At-least-once invocation is safe: a below-quorum
// evaluation changes nothing (ErrQuorumNotMet, no state change).
type Worker struct{ ctrl *Controller }

// NewWorker returns a retirement worker over ctrl.
func NewWorker(ctrl *Controller) *Worker { return &Worker{ctrl: ctrl} }

// EvaluateCutover reads the acknowledgements for target from ledgerEvents and runs the
// evidence-gated cutover. predecessor performs the fail-closed revoke + zeroize (in
// production, a signer-backed implementation that destroys the identity's predecessor
// key). A re-wrap gate (PCAS-14 / INT-12) may be threaded via ctrl's CutoverRequest
// PreRetire; here the standard cutover is run.
func (w *Worker) EvaluateCutover(ctx context.Context, target Target, successor Successor, retiredAlg string, successionRef []byte, ledgerEvents []events.Event, predecessor Predecessor, preRetire func(ctx context.Context) error, evalTime time.Time) (CutoverResult, error) {
	acks, err := AcksFromEvents(ledgerEvents)
	if err != nil {
		return CutoverResult{}, fmt.Errorf("retirement worker: read acks: %w", err)
	}
	return w.ctrl.Execute(ctx, CutoverRequest{
		Target:        target,
		Acks:          acks,
		Predecessor:   predecessor,
		Successor:     successor,
		RetiredAlg:    retiredAlg,
		SuccessionRef: successionRef,
		PreRetire:     preRetire,
	}, evalTime)
}

// FuncPredecessor adapts revoke/zeroize functions to a Predecessor. In production the
// zeroize function destroys the identity's predecessor key inside the signer
// (KeyHandle(identity, epoch)) over the transport, and revoke marks it revoked
// (fail-closed). Either nil function is a no-op.
type FuncPredecessor struct {
	RevokeFn  func(ctx context.Context, tenantID string) error
	ZeroizeFn func(ctx context.Context, tenantID string) error
}

// Revoke calls RevokeFn (fail-closed) if set.
func (p FuncPredecessor) Revoke(ctx context.Context, tenantID string) error {
	if p.RevokeFn == nil {
		return nil
	}
	return p.RevokeFn(ctx, tenantID)
}

// Zeroize calls ZeroizeFn if set.
func (p FuncPredecessor) Zeroize(ctx context.Context, tenantID string) error {
	if p.ZeroizeFn == nil {
		return nil
	}
	return p.ZeroizeFn(ctx, tenantID)
}
