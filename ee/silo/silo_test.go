// SPDX-License-Identifier: LicenseRef-trstctl-EE

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
	if got, err := tenancy.EventSubject(ctx, siloTenant, "events", "certificate.recorded"); err != nil || got != "events.t-acme-11111111111111111111111111111111.certificate.recorded" {
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
	if len(lanes) != 1 || lanes[0] != "t-acme-11111111111111111111111111111111" {
		t.Fatalf("subject lanes = %v, want [t-acme-11111111111111111111111111111111]", lanes)
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
	if targets.PostgresSchema != "t_11111111111111111111111111111111" || targets.JetStreamSubjectLane != "t-acme-11111111111111111111111111111111" {
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

// The isolation guarantee, structurally: two DISTINCT tenants must never share
// a Postgres schema, a JetStream subject lane, or an object-key prefix — those
// are the physical boundaries the sovereignty feature sells, and one shared
// boundary is one tenant able to reach another's data.
//
// The load-bearing case is the SLUG COLLISION. Slugs are operator free text
// with no charset validation, and lane derivation normalizes them lossily, so
// "acme-corp", "acme_corp" and "acme.corp" all collapse to the same readable
// part. Before the lane was keyed on the tenant ID, those three tenants shared
// ONE event lane — a cross-tenant breach. This proves distinct tenants stay
// disjoint on all three axes however their slugs collide.
func TestDistinctTenantsGetDisjointIsolationTargetsEvenWithCollidingSlugs(t *testing.T) {
	tenants := []Tenant{
		{ID: "aaaaaaaa-0000-0000-0000-000000000001", Slug: "acme-corp"},
		{ID: "bbbbbbbb-0000-0000-0000-000000000002", Slug: "acme_corp"}, // normalizes to the same readable part
		{ID: "cccccccc-0000-0000-0000-000000000003", Slug: "acme.corp"}, // and again
		{ID: "dddddddd-0000-0000-0000-000000000004", Slug: "globex"},
	}
	schemas := map[string]string{}
	lanes := map[string]string{}
	prefixes := map[string]string{}
	for _, tn := range tenants {
		schema := SchemaName(tn.ID)
		lane := SubjectLane(tn.ID, tn.Slug)
		prefix := ObjectPrefix(tn.ID)

		if prior, ok := schemas[schema]; ok {
			t.Fatalf("tenants %s and %s SHARE postgres schema %q — a siloed tenant could read the other's rows", prior, tn.ID, schema)
		}
		if prior, ok := lanes[lane]; ok {
			t.Fatalf("tenants %s and %s SHARE event lane %q — one tenant's events would land in the other's stream. "+
				"This is the slug-collision breach the ID-keyed lane exists to prevent.", prior, tn.ID, lane)
		}
		if prior, ok := prefixes[prefix]; ok {
			t.Fatalf("tenants %s and %s SHARE object prefix %q — one tenant could address the other's objects", prior, tn.ID, prefix)
		}
		schemas[schema] = tn.ID
		lanes[lane] = tn.ID
		prefixes[prefix] = tn.ID
	}

	// And no object prefix may be a PREFIX of another's, or a tenant could
	// enumerate another's key space by listing under a shorter prefix.
	all := make([]string, 0, len(prefixes))
	for p := range prefixes {
		all = append(all, p)
	}
	for i := range all {
		for j := range all {
			if i == j {
				continue
			}
			if strings.HasPrefix(all[i], all[j]) {
				t.Fatalf("object prefix %q is a prefix of %q — one tenant's key space contains another's", all[j], all[i])
			}
		}
	}
}
