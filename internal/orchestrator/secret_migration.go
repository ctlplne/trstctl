// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
)

// secretMigrationNamespace names secret.migration.* events by what they
// record, so a retried command converges on the event already appended.
var secretMigrationNamespace = uuid.MustParse("5c0f1e2a-8d43-5b7e-9a61-3f2d7c4b9e18")

// RecordSecretMigrationEvent appends one secret.migration.* event (A243)
// whose ID is derived from key: the run and what the event records (a batch,
// a consumer's read, the cutover). An event already appended under that ID
// is not appended again.
func (o *Orchestrator) RecordSecretMigrationEvent(ctx context.Context, tenantID, eventType, key string, payload any) error {
	eventID := uuid.NewSHA1(secretMigrationNamespace, []byte(tenantID+"\x00"+eventType+"\x00"+key)).String()
	if _, found, err := o.log.EventByID(ctx, eventID); err != nil || found {
		return err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = o.emitPrepared(ctx, events.Event{ID: eventID, Type: eventType, TenantID: tenantID, Data: data})
	return err
}
