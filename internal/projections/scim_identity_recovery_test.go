// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestSCIMIdentitySurvivesSnapshotAndEventRebuild(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)
	const subject = "opaque-recovery-subject"
	identity := &store.SCIMIdentity{UserName: "recovery@example.test", ExternalID: subject, SubjectAttribute: "externalId"}
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("SCIM recovery")})
	payload, err := json.Marshal(projections.TenantMemberUpserted{Subject: subject, SCIM: identity, Roles: []string{"viewer"}, Source: "scim"})
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, log, events.Event{Type: projections.EventTenantMemberUpserted, TenantID: tenantA, SchemaVersion: projections.TenantMemberSCIMSchemaVersion, Data: payload})
	// A historical/manual role event carries no provisioning metadata. It must
	// neither erase the binding nor change its schema-one payload contract.
	payload, err = json.Marshal(projections.TenantMemberUpserted{Subject: subject, Roles: []string{"operator"}, Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, log, events.Event{Type: projections.EventTenantMemberUpserted, TenantID: tenantA, SchemaVersion: 1, Data: payload})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	verify := func(wantStatus string) {
		t.Helper()
		member, err := s.GetTenantMember(ctx, tenantA, subject)
		if err != nil || !reflect.DeepEqual(member.SCIM, identity) || member.Status != wantStatus {
			t.Fatalf("restored identity=%+v status=%s err=%v", member.SCIM, member.Status, err)
		}
	}
	verify("active")
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	payload, err = json.Marshal(projections.TenantMemberOffboarded{Subject: subject, Reason: "retired"})
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, log, events.Event{Type: projections.EventTenantMemberOffboarded, TenantID: tenantA, SchemaVersion: 1, Data: payload})
	truncateReadModelAndCheckpoint(t, s)
	restored, err := p.RestoreFromSnapshot(ctx, log)
	if err != nil || !restored {
		t.Fatalf("snapshot restore=%v err=%v", restored, err)
	}
	verify("offboarded")
	if err := s.DeleteAllSnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	verify("offboarded")
}
