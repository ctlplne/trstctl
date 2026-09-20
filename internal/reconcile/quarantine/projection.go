// SPDX-License-Identifier: BUSL-1.1

package quarantine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/eventspec"
)

// StateProjection rebuilds tenant quarantine containment from the AN-2 event
// stream.
//
// Quarantine is a containment control, so its state may not live only in process
// memory. Before this projection existed a restart allocated an empty
// MemoryState, HasOpenTenantQuarantine answered false, and every quarantined
// tenant was silently admitted again -- a containment control that fails OPEN
// across a bounce.
//
// The durable substrate is the event log itself -- xrec.quarantine.entered and
// xrec.quarantine.released -- NOT a directly written state table: per AN-2 the
// state change IS the event and the read model is a projection of it. The core
// projector resets this projection and replays the log from sequence 0 on every
// boot (projections.Projector.ProjectCatchUp -> rebuildEventProjections), inside
// NewServer and before anything serves, so containment that was open before the
// restart is still open after it.
//
// AN-1, precisely: the AN-2 log is an append-only stream and rebuildEventProjections
// replays EVERY tenant's events through this fold with no per-tenant RLS context
// (contrast Projector.applyCore, which wraps store writes in store.WithTenant).
// Tenant isolation for this projection therefore comes from the fold itself, not
// from the substrate: foldTenantID binds every folded record to the event
// envelope's tenant_id and refuses an event whose payload names a different
// tenant, and every read filters by tenant. The projection materializes nothing
// outside this process, so it adds no cross-tenant row anywhere.
//
// Applying an event the command side already applied in-process is safe: enter
// and release are idempotent, so the inline writer and the tailing projector
// converge on the same state, and any transient divergence is an EXTRA open
// quarantine (fail closed), never a dropped one.
type StateProjection struct {
	mu        sync.Mutex
	state     *MemoryState
	watermark uint64
}

// NewStateProjection returns the containment fold writing into state. A nil state
// gets a fresh one so callers can register the projection unconditionally.
func NewStateProjection(state *MemoryState) *StateProjection {
	if state == nil {
		state = NewMemoryState()
	}
	return &StateProjection{state: state}
}

// Name identifies the projection to the core projector.
func (p *StateProjection) Name() string { return "xrec.quarantine.state" }

// Reset drops the folded containment state before a full replay.
func (p *StateProjection) Reset(context.Context) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.watermark = 0
	p.state.reset()
	return nil
}

// ReplayWatermark reports the highest sequence already folded so the core
// projector can skip at-least-once tail duplicates already covered by the boot
// replay. It is an optimization, never a correctness boundary: Apply is
// idempotent and replay order is sequence order.
func (p *StateProjection) ReplayWatermark() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.watermark
}

// Apply folds one event into the containment state.
//
// Error policy, chosen deliberately rather than by default. An EventProjection
// error propagates to catchUpReadModel and fails NewServer, so a hard error here
// stops the WHOLE control plane booting, for every tenant. That is the right
// answer for an AN-1 integrity violation -- an event whose payload tenant
// contradicts its envelope tenant could be folded into (or released from) the
// WRONG tenant's containment, and there is no safe guess -- and for a payload
// that will not decode at all. It is the wrong answer for an event that simply
// cannot be attributed (no tenant on either side) or that lacks
// authority/witness provenance: such an event names no tenant's containment, so
// skipping it loses no containment that could be attributed to anyone, while
// erroring would brick every tenant. Those are skipped, matching the precedent
// in rounds.DriftProjection.applyWitnessRecorded.
func (p *StateProjection) Apply(_ context.Context, ev eventspec.Event) error {
	if p == nil || p.state == nil {
		return nil
	}
	switch ev.Type {
	case EventTypeEntered:
		var payload Entered
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return fmt.Errorf("%w: decode %s: %v", ErrInvalidQuarantine, ev.Type, err)
		}
		tenantID, err := foldTenantID(ev, payload.TenantID)
		if err != nil {
			return err
		}
		authorityID := strings.TrimSpace(payload.AuthorityID)
		witnessID := strings.TrimSpace(payload.WitnessID)
		if tenantID == "" || authorityID == "" || witnessID == "" {
			break
		}
		p.state.enter(tenantID, authorityID, witnessID, payload.Reason, payload.EnteredAt)
	case EventTypeReleased:
		var payload Released
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return fmt.Errorf("%w: decode %s: %v", ErrInvalidCompletion, ev.Type, err)
		}
		tenantID, err := foldTenantID(ev, payload.TenantID)
		if err != nil {
			return err
		}
		authorityID := strings.TrimSpace(payload.AuthorityID)
		witnessID := strings.TrimSpace(payload.WitnessID)
		if tenantID == "" || authorityID == "" || witnessID == "" {
			break
		}
		p.state.release(tenantID, authorityID, witnessID)
	}
	p.mu.Lock()
	if ev.Sequence > p.watermark {
		p.watermark = ev.Sequence
	}
	p.mu.Unlock()
	return nil
}

// foldTenantID binds a folded record to the event envelope's tenant (AN-1). A
// payload naming a different tenant than the envelope is an integrity violation
// -- folding it either way could contain, or release, the wrong tenant -- so it
// is refused. An event carrying no tenant at all names no tenant's containment
// and is reported as unattributable ("" with no error) so the caller skips it
// rather than failing every tenant's boot.
func foldTenantID(ev eventspec.Event, payloadTenantID string) (string, error) {
	envelope := strings.TrimSpace(ev.TenantID)
	payload := strings.TrimSpace(payloadTenantID)
	switch {
	case envelope == "" && payload == "":
		return "", nil
	case envelope == "":
		return payload, nil
	case payload != "" && payload != envelope:
		return "", fmt.Errorf("%w: %s tenant mismatch: envelope %q payload %q", ErrInvalidQuarantine, ev.Type, envelope, payload)
	default:
		return envelope, nil
	}
}
