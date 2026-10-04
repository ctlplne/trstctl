// SPDX-License-Identifier: LicenseRef-trstctl-EE

package auditcompliance_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/auditcompliance"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestAuditRetentionPreservesProjectionRebuild pins the event-sourcing durability
// wall: audit retention may move old events out of the served audit view only
// when the advertised from-log rebuild still reproduces the exact served read model.
// Ordinary domain events are audit records too, so deleting an owner.created
// envelope without a durable projection-compaction baseline would make the next
// rebuild erase a still-live owner.
func TestAuditRetentionPreservesProjectionRebuild(t *testing.T) {
	ctx := context.Background()
	st := newAuditTestStore(t)
	log := openTestLog(t)
	projector := projections.New(st)

	old := time.Now().Add(-48 * time.Hour)
	if _, err := log.Append(ctx, events.Event{
		Type:     projections.EventTenantRegistered,
		TenantID: tenantA,
		Time:     old,
		Data:     tenantRegistered("Acme"),
	}); err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type:     projections.EventOwnerCreated,
		TenantID: tenantA,
		Time:     old.Add(time.Second),
		Data:     ownerCreated("00000000-0000-0000-0000-0000000000d1", "durable-owner"),
	}); err != nil {
		t.Fatalf("append owner: %v", err)
	}
	if err := projector.Project(ctx, log); err != nil {
		t.Fatalf("initial projection: %v", err)
	}
	if got := ownerCount(t, st, tenantA); got != 1 {
		t.Fatalf("owners before retention = %d, want 1", got)
	}

	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatalf("audit signing key: %v", err)
	}
	service := audit.NewService(log, key, audit.WithCheckpoints(st))
	worker := auditcompliance.NewRetentionWorker(
		service,
		log,
		auditcompliance.DirArchiver{Dir: t.TempDir()},
		st,
		time.Hour, key,
	)
	summary, err := worker.RunOnce(ctx)
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if summary.RecordsArchived != 2 || summary.RecordsSourceRetained != 2 ||
		summary.RecordsPruned != 0 {
		t.Fatalf("retention summary = %+v, want two archived and source-retained with zero pruned", summary)
	}

	// Simulate an event-only recovery target: PostgreSQL lost the logical
	// checkpoint as well as the served read model. The immutable audit.archived
	// event must rebuild that receiver, or archived history would reappear.
	if _, err := st.SystemPool().Exec(ctx, `TRUNCATE audit_checkpoints`); err != nil {
		t.Fatalf("clear audit checkpoints: %v", err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild after retention: %v", err)
	}
	if got := ownerCount(t, st, tenantA); got != 1 {
		t.Fatalf(
			"owners after retention rebuild = %d, want 1; retention deleted the authoritative owner.created event without a durable rebuild baseline",
			got,
		)
	}
	checkpoint, ok, err := st.LatestAuditCheckpoint(ctx, tenantA)
	if err != nil || !ok {
		t.Fatalf("rebuilt audit checkpoint: ok=%v err=%v", ok, err)
	}
	if checkpoint.RecordCount != 2 || checkpoint.BoundarySeq != 2 ||
		checkpoint.BoundaryHash == "" || checkpoint.ArchiveURI == "" {
		t.Fatalf("rebuilt audit checkpoint = %+v, want exact retired prefix", checkpoint)
	}
}

func TestLegacyAdministrativeAuditScopeRebuildsCheckpoint(t *testing.T) {
	ctx := context.Background()
	st := newAuditTestStore(t)
	log := openTestLog(t)
	const scope = "provider-control-plane"
	if _, err := log.Append(ctx, events.Event{
		Type: "provider.isolation.drill", TenantID: scope,
		Time: time.Now().Add(-48 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	svc := audit.NewService(log, key, audit.WithCheckpoints(st), audit.WithPrivacyErasures(st))
	worker := auditcompliance.NewRetentionWorker(svc, log, auditcompliance.DirArchiver{Dir: t.TempDir()}, st, time.Hour, key)
	if sum, err := worker.RunOnce(ctx); err != nil || sum.RecordsArchived != 1 {
		t.Fatalf("legacy retention = %+v, err = %v", sum, err)
	}
	assertCheckpoint := func(stage string) {
		t.Helper()
		cp, ok, err := st.LatestAuditCheckpoint(ctx, scope)
		if err != nil || !ok || cp.TenantID != scope || cp.RecordCount != 1 {
			t.Fatalf("%s checkpoint = %+v, ok = %v, err = %v", stage, cp, ok, err)
		}
		inventory, err := st.ListAuditCheckpointTenants(ctx)
		if err != nil || len(inventory) != 1 || inventory[0] != scope {
			t.Fatalf("%s scope inventory = %v, err = %v", stage, inventory, err)
		}
	}
	assertCheckpoint("live")
	assertAuditReadback := func(stage string) {
		t.Helper()
		records, err := svc.Search(ctx, audit.Query{TenantID: scope})
		if err != nil || len(records) != 1 || records[0].Type != audit.EventTypeArchived || records[0].TenantID != scope {
			t.Fatalf("%s scoped audit search = %+v, err = %v", stage, records, err)
		}
		if _, err := svc.VerifyChain(ctx, scope); err != nil {
			t.Fatalf("%s scoped audit chain: %v", stage, err)
		}
		signed, err := svc.Export(ctx, audit.Query{TenantID: scope})
		if err != nil {
			t.Fatalf("%s scoped audit export: %v", stage, err)
		}
		bundle, err := audit.VerifyBundle(signed, key.JWKS())
		if err != nil || bundle.TenantID != scope || bundle.Count != 1 || bundle.PrevHash == "" {
			t.Fatalf("%s scoped audit export = %+v, err = %v", stage, bundle, err)
		}
	}
	assertAuditReadback("live")
	if _, err := st.SystemPool().Exec(ctx, `TRUNCATE audit_checkpoints`); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch up legacy archive checkpoint: %v", err)
	}
	assertCheckpoint("catch-up")
	assertAuditReadback("catch-up")
	if _, err := st.SystemPool().Exec(ctx, `TRUNCATE audit_checkpoints`); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild legacy archive checkpoint: %v", err)
	}
	assertCheckpoint("replayed")
	assertAuditReadback("replayed")
}

func TestLegacyAdministrativeAuditScopeRejectsUnknownCoreEvent(t *testing.T) {
	ctx := context.Background()
	st := newAuditTestStore(t)
	log := openTestLog(t)
	if _, err := log.Append(ctx, events.Event{
		Type: "identity.issued", TenantID: "provider-control-plane",
	}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); err == nil {
		t.Fatal("unknown core event under textual Provider audit scope bypassed tenant isolation")
	}
}

func TestLegacyAdministrativeAuditScopeRejectsUnknownRetentionPartitionBeforeArchive(t *testing.T) {
	ctx := context.Background()
	st := newAuditTestStore(t)
	log := openTestLog(t)
	if _, err := log.Append(ctx, events.Event{
		Type: "identity.issued", TenantID: events.LegacyProviderGlobalAuditScope,
		Time: time.Now().Add(-48 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	svc := audit.NewService(log, key, audit.WithCheckpoints(st), audit.WithPrivacyErasures(st))
	worker := auditcompliance.NewRetentionWorker(svc, log, auditcompliance.DirArchiver{Dir: dir}, st, time.Hour, key)
	if _, err := worker.RunOnce(ctx); err == nil || !strings.Contains(err.Error(), "unsupported non-UUID event partition") {
		t.Fatalf("retention accepted unknown event in legacy partition: %v", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("refused retention wrote archive entries %v, err %v", entries, err)
	}
	if _, ok, err := st.LatestAuditCheckpoint(ctx, events.LegacyProviderGlobalAuditScope); err != nil || ok {
		t.Fatalf("refused retention sealed checkpoint: %v, %v", ok, err)
	}
	if _, err := st.ListPrivacyErasureRefs(ctx, "another-administrative-scope"); err == nil {
		t.Fatal("privacy lookup mapped an unknown textual scope into RLS")
	}
	if err := st.SaveAuditCheckpoint(ctx, audit.Checkpoint{TenantID: "another-administrative-scope"}); err == nil {
		t.Fatal("checkpoint storage mapped an unknown textual scope into RLS")
	}
}

func TestLegacyAdministrativeAuditPrivacyRefsStayInTheirRLSPartition(t *testing.T) {
	ctx := context.Background()
	st := newAuditTestStore(t)
	legacyStorage, err := store.AuditCheckpointRLSID(events.LegacyProviderGlobalAuditScope)
	if err != nil {
		t.Fatal(err)
	}
	const customer = "22222222-2222-2222-2222-222222222222"
	for _, row := range []struct{ tenant, ref string }{
		{legacyStorage, "legacy-subject-ref"},
		{customer, "customer-subject-ref"},
	} {
		if err := st.WithTenant(ctx, row.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO privacy_subject_erasures (tenant_id,subject_ref,erased_at) VALUES ($1,$2,now())`, row.tenant, row.ref)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, check := range []struct{ scope, want, absent string }{
		{events.LegacyProviderGlobalAuditScope, "legacy-subject-ref", "customer-subject-ref"},
		{customer, "customer-subject-ref", "legacy-subject-ref"},
	} {
		refs, err := st.ListPrivacyErasureRefs(ctx, check.scope)
		if err != nil || len(refs) != 1 {
			t.Fatalf("privacy refs for %s = %v, err %v", check.scope, refs, err)
		}
		if _, ok := refs[check.want]; !ok {
			t.Fatalf("privacy refs for %s missed %s", check.scope, check.want)
		}
		if _, ok := refs[check.absent]; ok {
			t.Fatalf("privacy refs for %s exposed %s", check.scope, check.absent)
		}
	}
}

func TestAuditRetentionRebuildRejectsLostSourceBeforeReadModelMutation(t *testing.T) {
	ctx := context.Background()
	st := newAuditTestStore(t)
	log := openTestLog(t)
	projector := projections.New(st)
	old := time.Now().Add(-48 * time.Hour)
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Time: old, Data: tenantRegistered("Acme"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA,
		Time: old.Add(time.Second),
		Data: ownerCreated("00000000-0000-0000-0000-0000000000d2", "preserve-on-failure"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := projector.Project(ctx, log); err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	service := audit.NewService(log, key, audit.WithCheckpoints(st))
	worker := auditcompliance.NewRetentionWorker(
		service, log, auditcompliance.DirArchiver{Dir: t.TempDir()}, st, time.Hour, key,
	)
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx, `TRUNCATE audit_checkpoints`); err != nil {
		t.Fatal(err)
	}
	//nolint:staticcheck // Deliberately reproduces legacy source loss so rebuild must fail closed.
	if err := log.PruneTenantThroughCheckpoint(ctx, tenantA, 2, nil); err != nil {
		t.Fatalf("simulate legacy source loss: %v", err)
	}

	err = projector.Rebuild(ctx, log)
	if err == nil || !strings.Contains(err.Error(), "refuse lossy rebuild") {
		t.Fatalf("Rebuild error = %v, want retained-source rejection", err)
	}
	if got := ownerCount(t, st, tenantA); got != 1 {
		t.Fatalf("failed rebuild mutated prior owner state: owners=%d, want 1", got)
	}
}
