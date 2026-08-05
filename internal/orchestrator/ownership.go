// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/projections"
)

// Ownership reconciliation as events (I2).
//
// AN-2: a reconcile is a state change like any other, and it goes through the
// log rather than straight into the read model. That matters more here than in
// most places — the whole value of this feature is being able to answer "where
// did this ownership come from, and what did we overrule to get it", and an
// answer that lives only in a mutable row cannot survive a rebuild.

// ReconcileOwnership records one owner's reconciliation against an external
// source: what was applied, with provenance, and what was refused.
//
// Both halves ride in ONE event. Emitting them separately would let a crash
// leave an estate whose ownership had changed with no record of the
// disagreements that were overruled to change it.
func (o *Orchestrator) ReconcileOwnership(ctx context.Context, tenantID string, in projections.OwnershipReconciled) error {
	if len(in.Applied) == 0 && len(in.Conflicts) == 0 {
		// Nothing happened. An event per no-op would fill the log with the
		// answer "the CMDB still agrees", which is the common case on every
		// scheduled sync.
		return nil
	}
	if in.ObservedAt.IsZero() {
		in.ObservedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventOwnershipReconciled, tenantID, payload)
	return err
}

// ConfigureCMDBSchedule records a tenant's standing instruction to re-read its
// CMDB. TokenRef is a reference, never a token value: a credential in an event
// is a credential in every backup and replica of the log.
func (o *Orchestrator) ConfigureCMDBSchedule(ctx context.Context, tenantID string, in projections.CMDBScheduleConfigured) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventCMDBScheduleConfigured, tenantID, payload)
	return err
}

// ResolveOwnershipConflict closes an ownership disagreement (I2).
//
// A resolution REQUIRES a reason. "Resolved" with no explanation tells the next
// reader nothing about which side was right, and a queue whose closed entries
// explain nothing is one people stop trusting — which is how the queue stops
// being read at all.
func (o *Orchestrator) ResolveOwnershipConflict(ctx context.Context, tenantID, id, by, resolution string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("orchestrator: no conflict named")
	}
	if strings.TrimSpace(by) == "" {
		return fmt.Errorf("orchestrator: a resolution needs the operator who made it; an " +
			"unattributed judgement cannot be questioned later")
	}
	if strings.TrimSpace(resolution) == "" {
		return fmt.Errorf("orchestrator: a resolution needs a reason. Closing a disagreement " +
			"without saying which side was right leaves the next reader exactly where they started")
	}
	payload, err := json.Marshal(projections.OwnershipConflictResolved{
		ID: id, ResolvedBy: strings.TrimSpace(by),
		Resolution: strings.TrimSpace(resolution), ResolvedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventOwnershipConflictResolved, tenantID, payload)
	return err
}
