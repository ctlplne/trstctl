// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// DestinationSCIMWriteback is the outbox destination of a directory writeback
// (A73): a change an operator made in trstctl to a member the directory
// provisioned, to be written to the directory's own SCIM endpoint by the
// licensed worker. Control-plane work; no agent claims it.
const DestinationSCIMWriteback = "scim.writeback"

// SCIMProvisionerActorRole is the actor role the SCIM handler stamps on the
// changes it applies. A change with this actor came from the directory and is
// never written back to it.
const SCIMProvisionerActorRole = "scim-provisioner"

// SCIMWritebackIntent names the member whose current state the worker writes
// back; it carries no member data, the worker reads the projected row.
type SCIMWritebackIntent struct {
	Subject       string `json:"subject"`
	Change        string `json:"change"`
	SourceEventID string `json:"source_event_id"`
}

// EnableSCIMWriteback names the tenants whose SCIM token writes back. Set at
// composition, before any member command runs.
func (o *Orchestrator) EnableSCIMWriteback(tenantIDs []string) {
	if o == nil {
		return
	}
	o.scimWritebackTenants = map[string]bool{}
	for _, id := range tenantIDs {
		if id = strings.TrimSpace(id); id != "" {
			o.scimWritebackTenants[id] = true
		}
	}
}

// enqueueSCIMWritebackTx queues the writeback for a member change inside the
// transaction that records it (AN-6), when the tenant writes back, the member
// is directory-owned (it carries a SCIM identity), and the change did not
// itself come from the directory.
func (o *Orchestrator) enqueueSCIMWritebackTx(ctx context.Context, tx pgx.Tx, event events.Event, subject, change string) error {
	if o == nil || o.outbox == nil || !o.scimWritebackTenants[event.TenantID] {
		return nil
	}
	if event.Actor != nil {
		for _, role := range event.Actor.Roles {
			if role == SCIMProvisionerActorRole {
				return nil
			}
		}
	}
	owned, err := o.store.TenantMemberDirectoryOwnedTx(ctx, tx, event.TenantID, subject)
	if err != nil || !owned {
		return err
	}
	payload, err := json.Marshal(SCIMWritebackIntent{Subject: subject, Change: change, SourceEventID: event.ID})
	if err != nil {
		return err
	}
	_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
		TenantID: event.TenantID, Destination: DestinationSCIMWriteback,
		IdempotencyKey: "scim-writeback:" + event.ID, Payload: payload,
		EffectLane: "scim-writeback:" + subject, RequiredAgentRole: "control_plane",
	})
	return err
}

// RecordSCIMWriteback appends the outcome of one writeback as audit evidence.
func (o *Orchestrator) RecordSCIMWriteback(ctx context.Context, tenantID string, recorded projections.SCIMWritebackRecorded) error {
	payload, err := json.Marshal(recorded)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventSCIMWritebackRecorded, tenantID, payload)
	return err
}
