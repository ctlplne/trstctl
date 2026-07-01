package projections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// ownerCreatedPayload is the v1 owner.created payload shape (mirrors
// projections.OwnerCreated). The SCHEMA-001 tests use it as the "old" payload an
// existing-but-evolved type would replace.
func ownerCreatedPayload(id, name string) []byte {
	b, _ := json.Marshal(struct {
		ID    string `json:"id"`
		Kind  string `json:"kind"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}{ID: id, Kind: "workload", Name: name, Email: name + "@example.com"})
	return b
}

func lifecycleTransitionPayload(identityID string, from, to orchestrator.State) []byte {
	b, _ := json.Marshal(struct {
		IdentityID string             `json:"identity_id"`
		From       orchestrator.State `json:"from"`
		To         orchestrator.State `json:"to"`
	}{IdentityID: identityID, From: from, To: to})
	return b
}

func tenantOffboardedPayload(rowsDeleted int) []byte {
	b, _ := json.Marshal(struct {
		RowsDeleted int `json:"rows_deleted"`
	}{RowsDeleted: rowsDeleted})
	return b
}

// TestBackupPreservesEventSchemaVersion is the DR regression for SCHEMA-001:
// backup/restore must carry the event envelope's schema version. Profile v2
// events contain the complete read-model row, while legacy v1 profile events are
// audit-only. If restore drops v=2, a disaster-recovery rebuild silently loses
// certificate_profiles.
func TestBackupPreservesEventSchemaVersion(t *testing.T) {
	srcStore := newStore(t)
	srcLog := openLog(t)
	ctx := events.ContextWithActor(context.Background(), events.Actor{Subject: "ra@a", Roles: []string{"ra-officer"}})
	if err := srcStore.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "A"}); err != nil {
		t.Fatal(err)
	}
	if _, err := srcLog.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("A")}); err != nil {
		t.Fatal(err)
	}

	orch := orchestrator.NewOrchestrator(srcLog, srcStore, orchestrator.NewOutbox(srcStore))
	spec1 := mustProfileSpec(t, profile.CertificateProfile{Name: "web", MaxValidity: profile.Duration(24 * time.Hour)})
	spec2 := mustProfileSpec(t, profile.CertificateProfile{Name: "web", MaxValidity: profile.Duration(48 * time.Hour)})
	v1, err := orch.CreateProfile(ctx, tenantA, "web", spec1)
	if err != nil {
		t.Fatalf("CreateProfile v1: %v", err)
	}
	v2, err := orch.CreateProfile(ctx, tenantA, "web", spec2)
	if err != nil {
		t.Fatalf("CreateProfile v2: %v", err)
	}

	var buf bytes.Buffer
	if _, err := backup.WriteLog(context.Background(), srcLog, &buf); err != nil {
		t.Fatalf("WriteLog: %v", err)
	}
	restoredLog := openLog(t)
	if _, err := backup.RestoreLog(context.Background(), restoredLog, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("RestoreLog: %v", err)
	}

	var profileVersions []int
	if err := restoredLog.Replay(context.Background(), 0, func(ev events.Event) error {
		if ev.Type == projections.EventProfileCreated || ev.Type == projections.EventProfileUpdated {
			profileVersions = append(profileVersions, ev.SchemaVersion)
		}
		return nil
	}); err != nil {
		t.Fatalf("Replay restored log: %v", err)
	}
	if len(profileVersions) != 2 {
		t.Fatalf("restored %d profile events, want 2", len(profileVersions))
	}
	for _, got := range profileVersions {
		if got != projections.ProfileEventSchemaVersion {
			t.Fatalf("restored profile schema versions = %v, want all %d", profileVersions, projections.ProfileEventSchemaVersion)
		}
	}

	dstStore := newStore(t)
	if err := projections.New(dstStore).Rebuild(context.Background(), restoredLog); err != nil {
		t.Fatalf("Rebuild restored log: %v", err)
	}
	got1, err := dstStore.GetProfileVersion(context.Background(), tenantA, "web", 1)
	if err != nil {
		t.Fatalf("GetProfileVersion v1 after restored rebuild: %v", err)
	}
	got2, err := dstStore.GetProfileVersion(context.Background(), tenantA, "web", 2)
	if err != nil {
		t.Fatalf("GetProfileVersion v2 after restored rebuild: %v", err)
	}
	active, err := dstStore.GetActiveProfile(context.Background(), tenantA, "web")
	if err != nil {
		t.Fatalf("GetActiveProfile after restored rebuild: %v", err)
	}
	if got1.ID != v1.ID || got1.Active {
		t.Errorf("restored v1 = id %s active %v, want id %s inactive", got1.ID, got1.Active, v1.ID)
	}
	if got2.ID != v2.ID || !got2.Active || active.ID != v2.ID {
		t.Errorf("restored v2/active = v2(%s active %v) active(%s), want v2 %s active", got2.ID, got2.Active, active.ID, v2.ID)
	}
	assertJSONEqual(t, got1.Spec, spec1)
	assertJSONEqual(t, got2.Spec, spec2)
}

// TestReplayOldEventsNewProjector is the SCHEMA-001 acceptance: a stream of
// version-1 events (the "old" payload shape) still projects and rebuilds
// correctly under the current projector, AND an event of a *known* type carrying a
// schema version the projector does not understand is rejected with a hard error
// rather than silently decoded against the wrong struct.
//
// This is the failure the schema-version field exists to catch: when an existing
// type's payload shape changes, the new events must declare a new version so a
// replay/rebuild can tell them apart from the old ones. Without the gate, a
// shape-changed payload would lenient-decode into the old struct and produce a
// wrong read model with no error on the most load-bearing (DR/rebuild) path.
func TestReplayOldEventsNewProjector(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	// A v1 stream: register the tenant, then create two owners with the baseline
	// (version-1) owner.created payload — exactly what today's command side emits.
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreatedPayload("11111111-aaaa-4aaa-8aaa-111111111111", "payments")}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreatedPayload("22222222-bbbb-4bbb-8bbb-222222222222", "billing")}); err != nil {
		t.Fatal(err)
	}

	// The old (v1) events project cleanly.
	if err := p.Project(ctx, log); err != nil {
		t.Fatalf("project v1 stream: %v", err)
	}
	owners, err := s.ListOwners(ctx, tenantA)
	if err != nil {
		t.Fatalf("ListOwners: %v", err)
	}
	if len(owners) != 2 {
		t.Fatalf("projected %d owners from the v1 stream, want 2", len(owners))
	}

	// And a Rebuild from the same v1 log reproduces the state (AN-2 / DR path).
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild v1 stream: %v", err)
	}
	owners2, err := s.ListOwners(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(owners2) != 2 {
		t.Fatalf("rebuild produced %d owners, want 2 (rebuild must reproduce the v1 read model)", len(owners2))
	}

	// Now simulate the dangerous case: a deployment changed owner.created's payload
	// shape and stamped it version 2, but this projector only knows version 1.
	// Appending and replaying such an event MUST fail (so the wrong shape is never
	// applied), not silently mis-project.
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA, SchemaVersion: 2,
		Data: ownerCreatedPayload("33333333-cccc-4ccc-8ccc-333333333333", "shipping"),
	}); err != nil {
		t.Fatal(err)
	}
	err = p.Project(ctx, log)
	if !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("projecting an owner.created v2 (unknown to this projector) err = %v, want ErrUnknownSchemaVersion", err)
	}
}

// TestApplyTxRejectsUnknownVersionForKnownType pins the gate at the ApplyTx unit
// level: a known event type at an unknown version is rejected, while the same
// type at the known version applies (SCHEMA-001).
func TestApplyTxRejectsUnknownVersionForKnownType(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	p := projections.New(s)

	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}

	// Known type, known version (1): applies.
	v1 := events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA, SchemaVersion: 1,
		Data: ownerCreatedPayload("44444444-dddd-4ddd-8ddd-444444444444", "ops"),
	}
	if err := p.Apply(ctx, v1); err != nil {
		t.Fatalf("Apply v1 owner.created: %v", err)
	}

	// Known type, unknown version (99): rejected — the wrong shape must never apply.
	v99 := events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA, SchemaVersion: 99,
		Data: ownerCreatedPayload("55555555-eeee-4eee-8eee-555555555555", "sre"),
	}
	if err := p.Apply(ctx, v99); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("Apply owner.created v99 err = %v, want ErrUnknownSchemaVersion", err)
	}

	// A wholly unknown *type* stays forward-compatible (ignored, not an error),
	// regardless of version — only known types are version-gated.
	unknown := events.Event{Type: "future.event.kind", TenantID: tenantA, SchemaVersion: 7, Data: []byte(`{}`)}
	if err := p.Apply(ctx, unknown); err != nil {
		t.Errorf("Apply of an unknown event type should be ignored, got %v", err)
	}
	unknownIdentityPrefix := events.Event{Type: "identity.future", TenantID: tenantA, SchemaVersion: 7, Data: []byte(`not-json`)}
	if err := p.Apply(ctx, unknownIdentityPrefix); err != nil {
		t.Errorf("Apply of an unknown identity.* event should be ignored until registered, got %v", err)
	}
}

// TestTenantLifecycleSchemaVersionGate pins SCHEMA-001 on the two tenant
// lifecycle events handled outside ApplyTx. They still decode payloads and mutate
// tenant-scoped state, so unknown versions must fail before the shortcut path
// applies either live or during rebuild.
func TestTenantLifecycleSchemaVersionGate(t *testing.T) {
	ctx := context.Background()

	t.Run("apply_rejects_unknown_tenant_registered_version", func(t *testing.T) {
		s := newStore(t)
		p := projections.New(s)
		ev := events.Event{
			Type:          projections.EventTenantRegistered,
			TenantID:      tenantA,
			SchemaVersion: 99,
			Data:          tenantRegistered("Acme"),
		}
		if err := p.Apply(ctx, ev); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
			t.Fatalf("Apply tenant.registered v99 err = %v, want ErrUnknownSchemaVersion", err)
		}
	})

	t.Run("rebuild_rejects_unknown_tenant_registered_version", func(t *testing.T) {
		s := newStore(t)
		log := openLog(t)
		p := projections.New(s)
		if _, err := log.Append(ctx, events.Event{
			Type:          projections.EventTenantRegistered,
			TenantID:      tenantA,
			SchemaVersion: 99,
			Data:          tenantRegistered("Acme"),
		}); err != nil {
			t.Fatal(err)
		}
		if err := p.Rebuild(ctx, log); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
			t.Fatalf("Rebuild tenant.registered v99 err = %v, want ErrUnknownSchemaVersion", err)
		}
	})

	t.Run("apply_rejects_unknown_tenant_offboarded_version", func(t *testing.T) {
		s := newStore(t)
		p := projections.New(s)
		ev := events.Event{
			Type:          projections.EventTenantOffboarded,
			TenantID:      tenantA,
			SchemaVersion: 99,
			Data:          tenantOffboardedPayload(2),
		}
		if err := p.Apply(ctx, ev); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
			t.Fatalf("Apply tenant.offboarded v99 err = %v, want ErrUnknownSchemaVersion", err)
		}
	})

	t.Run("rebuild_rejects_unknown_tenant_offboarded_version", func(t *testing.T) {
		s := newStore(t)
		log := openLog(t)
		p := projections.New(s)
		if _, err := log.Append(ctx, events.Event{
			Type:     projections.EventTenantRegistered,
			TenantID: tenantA,
			Data:     tenantRegistered("Acme"),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{
			Type:          projections.EventTenantOffboarded,
			TenantID:      tenantA,
			SchemaVersion: 99,
			Data:          tenantOffboardedPayload(2),
		}); err != nil {
			t.Fatal(err)
		}
		if err := p.Rebuild(ctx, log); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
			t.Fatalf("Rebuild tenant.offboarded v99 err = %v, want ErrUnknownSchemaVersion", err)
		}
	})
}

// TestLifecycleSchemaVersionGate extends SCHEMA-001 to the lifecycle transition
// path (SCHEMA-002): lifecycle events are decoded by projector code, so they must
// be version-gated like the other known event types.
func TestLifecycleSchemaVersionGate(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	p := projections.New(s)
	seedIdentity(t, s, tenantA)

	v99 := events.Event{
		Type:          projections.EventIdentityIssued,
		TenantID:      tenantA,
		SchemaVersion: 99,
		Data:          lifecycleTransitionPayload(idIdentity, orchestrator.StateRequested, orchestrator.StateIssued),
	}
	if err := p.Apply(ctx, v99); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("Apply lifecycle v99 err = %v, want ErrUnknownSchemaVersion", err)
	}

	v1 := events.Event{
		Type:          projections.EventIdentityIssued,
		TenantID:      tenantA,
		SchemaVersion: 1,
		Data:          lifecycleTransitionPayload(idIdentity, orchestrator.StateRequested, orchestrator.StateIssued),
	}
	if err := p.Apply(ctx, v1); err != nil {
		t.Fatalf("Apply lifecycle v1: %v", err)
	}
	ident, err := s.GetIdentity(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if ident.Status != string(orchestrator.StateIssued) {
		t.Fatalf("identity status after lifecycle v1 = %q, want issued", ident.Status)
	}

	v2Payload, err := json.Marshal(struct {
		IdentityID     string             `json:"identity_id"`
		From           orchestrator.State `json:"from"`
		To             orchestrator.State `json:"to"`
		IdempotencyKey string             `json:"idempotency_key"`
	}{IdentityID: idIdentity, From: orchestrator.StateIssued, To: orchestrator.StateRevoked, IdempotencyKey: "transition-idem"})
	if err != nil {
		t.Fatal(err)
	}
	v2 := events.Event{
		Type:          projections.EventIdentityRevoked,
		TenantID:      tenantA,
		SchemaVersion: projections.LifecycleEventSchemaVersion,
		Data:          v2Payload,
	}
	if err := p.Apply(ctx, v2); err != nil {
		t.Fatalf("Apply lifecycle v2: %v", err)
	}
	ident, err = s.GetIdentity(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if ident.Status != string(orchestrator.StateRevoked) {
		t.Fatalf("identity status after lifecycle v2 = %q, want revoked", ident.Status)
	}
}
