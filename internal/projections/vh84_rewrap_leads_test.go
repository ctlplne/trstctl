// SPDX-License-Identifier: BUSL-1.1

package projections_test

// VH84 (R1 verify): follow-on leads VH83-N1. Applies on top of repro/S7-L3.patch and
// repro/PLAN-SIB-55.vh83.patch (reuses newVH83Rig, hex64).

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func vh84Append(t *testing.T, rig vh83Rig, tenant, epoch, name, id, typ, surface string, m projections.ApplicationSecretMutation, seed byte) {
	t.Helper()
	ctx := context.Background()
	m.TenantEpoch, m.Name, m.Surface = epoch, name, surface
	m.IdempotencyKeyDigest, m.RequestBinding, m.CommandEvidence = hex64(seed), hex64(seed+1), hex64(seed+2)
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.log.Append(ctx, events.Event{
		ID: id, Type: typ, TenantID: tenant, Time: time.Now().UTC(),
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: payload,
	}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(rig.s).ProjectCatchUp(ctx, rig.log); err != nil {
		t.Fatalf("project %s (%s): %v", typ, m.Action, err)
	}
}

func vh84OutboxSealed(t *testing.T, rig vh83Rig, tenant string) []byte {
	t.Helper()
	var raw []byte
	if err := rig.s.SystemPool().QueryRow(context.Background(),
		`SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'secret.sync.ci'`, tenant).Scan(&raw); err != nil {
		t.Fatalf("read the retained secret-sync outbox row: %v", err)
	}
	var binding struct {
		Sealed []byte `json:"sealed"`
	}
	if err := json.Unmarshal(raw, &binding); err != nil {
		t.Fatal(err)
	}
	return binding.Sealed
}

// Lead 1: the embedded payload.Sync of a connector-rotation application-secret event
// (api/secrets_connector_rotation.go:384 shape) after a rewrap.
func vh84EmbeddedSync(t *testing.T, tenant, mode string) {
	ctx := context.Background()
	rig := newVH83Rig(t, tenant, mode)
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	const name = "vh84/api/token"
	aad := []byte(tenant + "/secret-store/" + name)
	vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-0000000084f1", projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1, Sealed: rig.seal("value-one", aad)}, '1')
	const rotateID = "a7770000-0000-4000-8000-0000000084f2"
	jobID := store.DurableSecretSyncJobID(tenant, rotateID)
	syncAAD := []byte(tenant + "/secret-sync/ci/" + jobID + "/TOKEN")
	syncSealed := rig.seal("value-two", syncAAD)
	vh84Append(t, rig, tenant, epoch, name, rotateID, projections.EventApplicationSecretRotated, "rotation",
		projections.ApplicationSecretMutation{Action: "rotate", ExpectedVersion: 1, ResultVersion: 2, Sealed: rig.seal("value-two", aad),
			Sync: &projections.SecretSyncQueued{ID: jobID, SecretName: name, SecretVersion: 2, Target: "ci", RemoteKey: "TOKEN",
				ValueDigest: hex64('c'), IdempotencyKey: store.SecretSyncOutboxIdempotencyKey("ci", jobID),
				RequestBinding: hex64('5'), Sealed: syncSealed}}, '4')
	before := vh84OutboxSealed(t, rig, tenant)
	if !bytes.Equal(before, syncSealed) {
		t.Fatal("setup: the outbox row does not carry the embedded sync's sealed copy")
	}
	if err := projections.New(rig.s).Rebuild(ctx, rig.log); err != nil {
		t.Fatalf("control: rebuild before the %s: %v", mode, err)
	}
	rig.rewrap()
	after := vh84OutboxSealed(t, rig, tenant)
	if err := rig.open(after, syncAAD); err != nil {
		t.Fatalf("control: the retained outbox copy does not open after the %s: %v", mode, err)
	}
	t.Logf("%s: retained outbox sealed copy changed=%t", mode, !bytes.Equal(before, after))
	if err := vh83RecoveryProjector(t, rig).Rebuild(ctx, rig.log); err != nil {
		t.Fatalf("VH84 lead 1 (%s): full rebuild stops on the embedded-sync rotate event: %v", mode, err)
	}
	t.Logf("%s: rebuild succeeded", mode)
}

func TestVH84EmbeddedSyncRebuildAfterAKeyDomainMigration(t *testing.T) {
	vh84EmbeddedSync(t, "a7770000-0000-4000-8000-000000008401", "migrate")
}

func TestVH84EmbeddedSyncRebuildAfterADeploymentKEKRotation(t *testing.T) {
	vh84EmbeddedSync(t, "a7770000-0000-4000-8000-000000008402", "rotate")
}

// Leads 3+4: the --full-restore-dir first rebuild runs before the PostgreSQL import
// (internal/server/backup.go:810 then :840), i.e. on a target with no receipts, no
// secret rows, no epoch row and no outbox. Simulated by deleting the tenant's
// independent rows before Rebuild.
func vh84FreshTarget(t *testing.T, tenant, mode string) {
	ctx := context.Background()
	rig := newVH83Rig(t, tenant, mode)
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	const jobID = "a7770000-0000-4000-8000-0000000084a1"
	syncSealed := rig.seal("sync-value", []byte(tenant+"/secret-sync/ci/"+jobID+"/OTHER"))
	syncPayload, err := json.Marshal(projections.SecretSyncQueued{
		TenantEpoch: epoch, ID: jobID, SecretName: "vh84/other", SecretVersion: 1,
		Target: "ci", RemoteKey: "OTHER", ValueDigest: hex64('a'),
		IdempotencyKey: store.SecretSyncOutboxIdempotencyKey("ci", jobID), RequestBinding: hex64('b'),
		Sealed: syncSealed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.log.Append(ctx, events.Event{
		ID: store.SecretSyncQueuedEventID(tenant, jobID), Type: projections.EventSecretSyncQueued,
		TenantID: tenant, Time: time.Now().UTC(),
		SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: syncPayload,
	}); err != nil {
		t.Fatal(err)
	}
	const name = "vh84/db/password"
	aad := []byte(tenant + "/secret-store/" + name)
	vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-0000000084e1", projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1, Sealed: rig.seal("value-one", aad)}, '1')
	v1, err := rig.s.GetSecretVersionAt(ctx, tenant, name, time.Now().UTC())
	if err != nil || v1.Version != 1 {
		t.Fatalf("v1 = %+v err=%v", v1.Version, err)
	}
	time.Sleep(5 * time.Millisecond)
	vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-0000000084e2", projections.EventApplicationSecretRotated, "native",
		projections.ApplicationSecretMutation{Action: "rotate", ExpectedVersion: 1, ResultVersion: 2, Sealed: rig.seal("value-two", aad)}, '4')
	vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-0000000084e3", projections.EventApplicationSecretRecovered, "native",
		projections.ApplicationSecretMutation{Action: "recover", ExpectedVersion: 2, ResultVersion: 3, Sealed: v1.Sealed,
			SourceVersion: 1, SourceWrittenAt: v1.WrittenAt.UTC()}, '7')
	wipe := func(label string) {
		t.Helper()
		for _, table := range []string{"application_secret_mutation_receipts", "secret_store_versions",
			"secret_store", "application_secret_tenant_epochs"} {
			if _, err := rig.s.SystemPool().Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = $1`, tenant); err != nil {
				t.Fatalf("%s: clear %s for the fresh-target shape: %v", label, table, err)
			}
		}
	}
	state := func(label string) {
		t.Helper()
		var receipts, versions int
		_ = rig.s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM application_secret_mutation_receipts WHERE tenant_id = $1`, tenant).Scan(&receipts)
		_ = rig.s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM secret_store_versions WHERE tenant_id = $1`, tenant).Scan(&versions)
		t.Logf("%s: receipts=%d versions=%d", label, receipts, versions)
	}
	wipe("control")
	if err := projections.New(rig.s).Rebuild(ctx, rig.log); err != nil {
		t.Fatalf("control: fresh-target rebuild before the %s: %v", mode, err)
	}
	state("control (fresh target, before the " + mode + ")")
	rig.rewrap()
	wipe("after")
	err = vh83RecoveryProjector(t, rig).Rebuild(ctx, rig.log)
	state("fresh target after the " + mode)
	if err != nil {
		t.Fatalf("VH84 leads 3+4 (%s): fresh-target rebuild (no receipts) stops: %v", mode, err)
	}
	t.Logf("%s: fresh-target rebuild succeeded", mode)
}

func TestVH84FreshTargetRebuildAfterAKeyDomainMigration(t *testing.T) {
	vh84FreshTarget(t, "a7770000-0000-4000-8000-000000008403", "migrate")
}

func TestVH84FreshTargetRebuildAfterADeploymentKEKRotation(t *testing.T) {
	vh84FreshTarget(t, "a7770000-0000-4000-8000-000000008404", "rotate")
}
