// SPDX-License-Identifier: BUSL-1.1
package projections_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A claimed application-secret command carries sealed command bytes that the
// current history/hot-state rewrapper does not visit. Migration must wait for
// its append/projection to settle instead of stranding an unopenable retry.
func TestRewrapMigrationRefusesUnresolvedSecretMutationFence(t *testing.T) {
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009301"
	rig := newVH83Rig(t, tenant, "migrate")
	const name = "rewrap/pending-command"
	claimed, err := rig.s.ClaimApplicationSecretMutationFence(ctx, store.ApplicationSecretMutationFence{
		TenantID: tenant, Name: name, Operation: "create",
		EventID:        "a7770000-0000-4000-8000-000000009302",
		EventType:      projections.EventApplicationSecretCreated,
		SchemaVersion:  projections.ApplicationSecretMutationSchemaVersion,
		RequestBinding: hex64('b'),
		Payload:        []byte(`{"action":"create","sealed":"test-container"}`),
	})
	if err != nil {
		t.Fatalf("claim pending command: %v", err)
	}
	if err := rig.tryMigrate(); err == nil {
		t.Fatal("tenant key-domain migration accepted an unresolved sealed mutation fence")
	}
	remaining, err := rig.s.GetApplicationSecretMutationFence(ctx, tenant, name)
	if err != nil || remaining.EventID != claimed.EventID || !bytes.Equal(remaining.Payload, claimed.Payload) {
		t.Fatalf("refused rewrap changed pending command: remaining=%+v err=%v", remaining, err)
	}
}

// CR-045: a deployment-wide key rotation must see every tenant's pending
// application-secret command before it records its first rotation snapshot.
func TestRewrapDeploymentRotationRefusesUnresolvedSecretMutationFence(t *testing.T) {
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009311"
	rig := newVH83Rig(t, tenant, "rotate")
	const name = "rewrap/pending-rotation-command"
	claimed, err := rig.s.ClaimApplicationSecretMutationFence(ctx, store.ApplicationSecretMutationFence{
		TenantID: tenant, Name: name, Operation: "create",
		EventID:        "a7770000-0000-4000-8000-000000009312",
		EventType:      projections.EventApplicationSecretCreated,
		SchemaVersion:  projections.ApplicationSecretMutationSchemaVersion,
		RequestBinding: hex64('d'),
		Payload:        []byte(`{"action":"create","sealed":"test-container"}`),
	})
	if err != nil {
		t.Fatalf("claim pending command: %v", err)
	}
	if err := rig.tryRotate(); err == nil {
		t.Fatal("deployment key rotation accepted an unresolved sealed mutation fence")
	}
	remaining, err := rig.s.GetApplicationSecretMutationFence(ctx, tenant, name)
	if err != nil || remaining.EventID != claimed.EventID || !bytes.Equal(remaining.Payload, claimed.Payload) {
		t.Fatalf("refused rotation changed pending command: remaining=%+v err=%v", remaining, err)
	}
}
