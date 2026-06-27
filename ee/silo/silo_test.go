package silo

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/tenancy"
)

const (
	siloTenant   = "11111111-1111-1111-1111-111111111111"
	pooledTenant = "22222222-2222-2222-2222-222222222222"
)

func TestRouterRoutesSiloedTenantToPhysicalTargetsAndLeavesPooledTenantAlone(t *testing.T) {
	ctx := context.Background()
	reg := NewMemRegistry()
	reg.Upsert(Tenant{ID: siloTenant, Slug: "acme", Model: tenancy.IsolationSiloed, Status: TenantActive})
	reg.Upsert(Tenant{ID: pooledTenant, Slug: "globex", Model: tenancy.IsolationPooled, Status: TenantActive})
	router := NewRouter(reg, time.Minute)

	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	if got, err := tenancy.PostgresSchema(ctx, siloTenant); err != nil || got != "t_11111111111111111111111111111111" {
		t.Fatalf("silo postgres schema = %q err=%v", got, err)
	}
	if got, err := tenancy.EventSubject(ctx, siloTenant, "events", "certificate.recorded"); err != nil || got != "events.t-acme.certificate.recorded" {
		t.Fatalf("silo event subject = %q err=%v", got, err)
	}
	if got, err := tenancy.ObjectPrefix(ctx, siloTenant); err != nil || got != "silo/11111111-1111-1111-1111-111111111111/" {
		t.Fatalf("silo object prefix = %q err=%v", got, err)
	}

	if got, err := tenancy.PostgresSchema(ctx, pooledTenant); err != nil || got != "" {
		t.Fatalf("pooled postgres schema = %q err=%v, want pooled", got, err)
	}
	if got, err := tenancy.EventSubject(ctx, pooledTenant, "events", "certificate.recorded"); err != nil || got != "events.certificate.recorded" {
		t.Fatalf("pooled event subject = %q err=%v", got, err)
	}
	if got, err := tenancy.ObjectPrefix(ctx, pooledTenant); err != nil || got != "tenant/"+pooledTenant+"/" {
		t.Fatalf("pooled object prefix = %q err=%v", got, err)
	}

	lanes, err := router.JetStreamSubjectLanes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(lanes) != 1 || lanes[0] != "t-acme" {
		t.Fatalf("subject lanes = %v, want [t-acme]", lanes)
	}
}

func TestProvisionerIsIdempotentRecreatesRLSAndTearsDownCleanly(t *testing.T) {
	ctx := context.Background()
	plane := NewMemPlane()
	provisioner := NewProvisioner(plane, []string{"agents", "certificates"})
	tenant := Tenant{ID: siloTenant, Slug: "acme", Model: tenancy.IsolationSiloed, Status: TenantActive}

	targets, err := provisioner.Provision(ctx, tenant)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := provisioner.Provision(ctx, tenant); err != nil {
		t.Fatalf("idempotent reprovision: %v", err)
	}
	if targets.PostgresSchema != "t_11111111111111111111111111111111" || targets.JetStreamSubjectLane != "t-acme" {
		t.Fatalf("targets = %+v", targets)
	}
	if n := plane.EnsureCount(targets.PostgresSchema); n != 1 {
		t.Fatalf("schema ensured %d times, want idempotent once", n)
	}
	ddl := strings.Join(plane.SchemaDDL(targets.PostgresSchema), "\n")
	for _, want := range []string{"ENABLE ROW LEVEL SECURITY", "FORCE ROW LEVEL SECURITY", "current_setting('trstctl.tenant_id'", "CREATE POLICY tenant_isolation"} {
		if !strings.Contains(ddl, want) {
			t.Fatalf("provision plan missing %q:\n%s", want, ddl)
		}
	}
	if !plane.HasEventLane(targets.JetStreamSubjectLane) || !plane.HasObjectPrefix(targets.ObjectKeyPrefix) {
		t.Fatalf("stream/object targets not provisioned: %+v", targets)
	}

	if err := provisioner.Teardown(ctx, tenant); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if plane.HasSchema(targets.PostgresSchema) || plane.HasEventLane(targets.JetStreamSubjectLane) || plane.HasObjectPrefix(targets.ObjectKeyPrefix) {
		t.Fatalf("teardown left isolated targets behind: %+v", targets)
	}
}

func TestUnlicensedDefaultRemainsSinglePooledShape(t *testing.T) {
	tenancy.SetRouter(nil)

	if got, err := tenancy.PostgresSchema(context.Background(), siloTenant); err != nil || got != "" {
		t.Fatalf("default postgres route = %q err=%v, want pooled", got, err)
	}
	if got, err := tenancy.EventSubject(context.Background(), siloTenant, "events", "certificate.recorded"); err != nil || got != "events.certificate.recorded" {
		t.Fatalf("default event route = %q err=%v, want pooled", got, err)
	}
	if got, err := tenancy.ObjectPrefix(context.Background(), siloTenant); err != nil || got != "tenant/"+siloTenant+"/" {
		t.Fatalf("default object prefix = %q err=%v, want pooled", got, err)
	}
}
