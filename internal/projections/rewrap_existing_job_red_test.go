// SPDX-License-Identifier: BUSL-1.1
package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// An existing projected job is another authority-bearing copy of the sealed
// sync command. A replay with identical metadata but new payload encryption
// cannot borrow the job's outbox ID.
func TestRewrapExistingSecretSyncJobRejectsFreshPayloadEncryption(t *testing.T) {
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009101"
	const jobID = "a7770000-0000-4000-8000-000000009102"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte(tenant + "/secret-sync/ci/" + jobID + "/VALUE")
	queued := projections.SecretSyncQueued{
		TenantEpoch: epoch, ID: jobID, SecretName: "rewrap/existing-job", SecretVersion: 1,
		Target: "ci", RemoteKey: "VALUE", ValueDigest: hex64('a'),
		IdempotencyKey: store.SecretSyncOutboxIdempotencyKey("ci", jobID), RequestBinding: hex64('b'),
		Sealed: rig.seal("same-value", aad),
	}
	data, err := json.Marshal(queued)
	if err != nil {
		t.Fatal(err)
	}
	event, err := rig.log.Append(ctx, events.Event{
		ID: store.SecretSyncQueuedEventID(tenant, jobID), Type: projections.EventSecretSyncQueued,
		TenantID: tenant, Time: time.Now().UTC(),
		SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(rig.s).Apply(ctx, event); err != nil {
		t.Fatalf("project original sync intent: %v", err)
	}
	queued.Sealed = rig.seal("same-value", aad) // fresh DEK and payload nonce
	event.Data, err = json.Marshal(queued)
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(rig.s, rewrapPairOption(rig)).Apply(ctx, event); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("fresh payload encryption of an existing sync job = %v, want conflict", err)
	}
}
