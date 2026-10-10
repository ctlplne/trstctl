// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
)

// These indexes contain only immutable event envelopes. Boot replay rebuilds
// them before the agent channel serves. A signed report therefore reads the
// exact prior event without invoking Log.Replay's full-history safety preflight
// inside the agent's acknowledgement deadline.
func cloneReceiptEvent(ev eventspec.Event) eventspec.Event {
	ev.Data = append([]byte(nil), ev.Data...)
	return ev
}

func (p *ProgressProjection) hostPreparedReceipt(tenantID, runID, assetID string) (TLSFindingPrepared, bool, error) {
	if p == nil {
		return TLSFindingPrepared{}, false, errors.New("pqcmigration: host receipt projection is unavailable")
	}
	p.mu.RLock()
	ev, found := p.preparedEvents[progressKey{tenantID: tenantID, runID: runID, assetID: assetID}]
	p.mu.RUnlock()
	if !found {
		return TLSFindingPrepared{}, false, nil
	}
	var prepared TLSFindingPrepared
	if err := json.Unmarshal(ev.Data, &prepared); err != nil {
		return TLSFindingPrepared{}, false, err
	}
	return prepared, true, nil
}

func (p *ProgressProjection) hostCompletedReceipt(tenantID, runID, assetID string) (TLSFindingCompleted, bool, error) {
	if p == nil {
		return TLSFindingCompleted{}, false, errors.New("pqcmigration: host receipt projection is unavailable")
	}
	p.mu.RLock()
	ev, found := p.completedEvents[progressKey{tenantID: tenantID, runID: runID, assetID: assetID}]
	p.mu.RUnlock()
	if !found {
		return TLSFindingCompleted{}, false, nil
	}
	var completed TLSFindingCompleted
	if err := json.Unmarshal(ev.Data, &completed); err != nil {
		return TLSFindingCompleted{}, false, err
	}
	return completed, true, nil
}

func (p *ProgressProjection) hostRollbackReceipt(tenantID, runID, targetID string) (TLSFindingRollbackCompleted, bool, error) {
	if p == nil {
		return TLSFindingRollbackCompleted{}, false, errors.New("pqcmigration: host receipt projection is unavailable")
	}
	p.mu.RLock()
	ev, found := p.rollbackEvents[progressRollbackKey{tenantID: tenantID, runID: runID, targetID: targetID}]
	p.mu.RUnlock()
	if !found {
		return TLSFindingRollbackCompleted{}, false, nil
	}
	var completed TLSFindingRollbackCompleted
	if err := json.Unmarshal(ev.Data, &completed); err != nil {
		return TLSFindingRollbackCompleted{}, false, err
	}
	return completed, true, nil
}

func (p *ProgressProjection) pendingHostReceipt(id string) (eventspec.Event, bool) {
	p.mu.RLock()
	ev, found := p.pendingEvents[id]
	p.mu.RUnlock()
	return cloneReceiptEvent(ev), found
}

func (p *ProgressProjection) retainPendingHostReceipt(ev eventspec.Event) {
	p.mu.Lock()
	if p.pendingEvents == nil {
		p.pendingEvents = map[string]eventspec.Event{}
	}
	p.pendingEvents[ev.ID] = cloneReceiptEvent(ev)
	p.mu.Unlock()
}

func (p *ProgressProjection) clearPendingHostReceipt(id string) {
	p.mu.Lock()
	delete(p.pendingEvents, id)
	p.mu.Unlock()
}

func hostReceiptEventID(tenantID, runID, findingOrTargetID, eventType string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("pqc-host-receipt\x00"+tenantID+"\x00"+
		runID+"\x00"+findingOrTargetID+"\x00"+eventType)).String()
}

// appendHostReceiptEvent gives a repeated signed report one stable event ID.
// A projection failure after append retains the acknowledged envelope in
// memory for retry; a process restart reconstructs it from the immutable log.
// A duplicate broker ACK is checked byte-for-byte before projecting.
func (h HostAgentHooks) appendHostReceiptEvent(ctx context.Context, tenantID, runID, findingOrTargetID,
	eventType string, payload any) error {
	if h.Store == nil || h.Log == nil || h.Progress == nil {
		return errors.New("pqcmigration: host receipt requires store, event log, and progress projection")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	id := hostReceiptEventID(tenantID, runID, findingOrTargetID, eventType)
	ev, pending := h.Progress.pendingHostReceipt(id)
	if !pending {
		ev, err = h.Log.Append(ctx, events.Event{ID: id, Type: eventType, TenantID: tenantID, Data: data})
		if err != nil {
			return err
		}
	}
	if ev.ID != id || ev.Type != eventType || ev.TenantID != tenantID || !bytes.Equal(ev.Data, data) {
		return fmt.Errorf("pqcmigration: host receipt event %s conflicts with its durable predecessor", id)
	}
	h.Progress.retainPendingHostReceipt(ev)
	if err := projections.New(h.Store, WithProgressProjection(h.Progress)).Apply(ctx, ev); err != nil {
		return err
	}
	h.Progress.clearPendingHostReceipt(id)
	return nil
}
