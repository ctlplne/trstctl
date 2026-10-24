// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/store"
)

// QueueOwnerHandoffNotice tells an owner that stale NHIs were handed to them
// (A101): one ownership-channel notice naming the records and the reason,
// addressed to the owner and their escalation chain. key makes a retried
// handoff converge on one notice. It reports whether the notice was queued.
func (o *Orchestrator) QueueOwnerHandoffNotice(ctx context.Context, tenantID, ownerID string, inventoryIDs []string, reason, key string) (bool, error) {
	if o.outbox == nil {
		return false, nil
	}
	owner, err := o.store.GetOwner(ctx, tenantID, ownerID)
	if err != nil {
		return false, err
	}
	chain, err := store.OwnerEscalationChain(owner.EscalationChain)
	if err != nil {
		return false, err
	}
	var recipients []notify.AlertRecipient
	if owner.Email != "" {
		recipients = append(recipients, notify.AlertRecipient{Kind: "owner", Subject: owner.ID, DisplayName: owner.Name, Email: owner.Email})
	}
	for _, recipient := range chain {
		recipients = append(recipients, notify.AlertRecipient{Kind: "escalation", Subject: recipient, Email: recipient})
	}
	alert := notify.Alert{
		Kind: notify.KindOwnershipHandoff, TenantID: tenantID,
		OwnerID: owner.ID, OwnerName: owner.Name, OwnerEmail: owner.Email,
		Detail: fmt.Sprintf("%d stale NHI(s) were handed to you (%s): %s. Reattest the ones still in use; revoke or retire the rest.",
			len(inventoryIDs), strings.TrimSpace(reason), strings.Join(inventoryIDs, ", ")),
		Severity: notify.AlertSeverityWarning, EscalationRecipients: recipients,
	}
	payload, err := json.Marshal(alert)
	if err != nil {
		return false, err
	}
	queued := false
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: notify.DestinationOwnership,
			IdempotencyKey: "ownership-handoff:" + key, Payload: payload,
		})
		queued = inserted
		return err
	})
	return queued, err
}
