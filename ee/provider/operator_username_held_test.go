// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/eventstest"

	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

// TestProviderOperatorUnderAHeldUserNameAppliesWithoutTakingItLS1L2
// (PostgreSQL and the embedded log): an operator event naming a userName
// another operator holds (one appended before SCIM checked it) failed the
// provider_operators (tenant_id, user_name) index live. It is applied without
// taking the name: a new operator is not created, an existing one takes the
// rest of its state (an offboard lands) and keeps its own userName, and a
// rebuild from the log reaches the same rows.
func TestProviderOperatorUnderAHeldUserNameAppliesWithoutTakingItLS1L2(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	projection := NewAuthorityProjection(st)
	mutations := NewEventMutationSink(log, projection)
	now := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	operator := func(key, typ, id, externalID, userName string, active bool) error {
		identity := OperatorIdentity{ID: id, ExternalID: externalID, UserName: userName, Email: userName,
			Active: active, Source: "scim:ls1l2", CreatedAt: now, UpdatedAt: now}
		if !active {
			identity.DeprovisionedAt = now
		}
		_, err := mutations.Append(ctx, key, typ, providerAuthorityTenant, AuthorityEvent{
			Operator: &identity, EffectiveAt: now,
			Audit: AuditEvent{Type: typ, TenantID: providerAuthorityTenant, OperatorID: "scim:ls1l2", Subject: id, At: now},
		})
		return err
	}
	for _, step := range []struct {
		key, typ, id, externalID, userName string
		active                             bool
	}{
		{"ls1l2-alice", EventOperatorUpserted, "ls1l2-op-alice", "okta-alice", "alice@example.test", true},
		{"ls1l2-carol", EventOperatorUpserted, "ls1l2-op-carol", "okta-carol", "carol@example.test", true},
		// A new external ID under alice's userName: not created.
		{"ls1l2-alice-again", EventOperatorUpserted, "ls1l2-op-alice2", "okta-alice-2", "alice@example.test", true},
		// Carol offboarded in an event that names alice's userName: the
		// offboard lands and carol keeps her own userName.
		{"ls1l2-carol-off", EventOperatorOffboarded, "ls1l2-op-carol", "okta-carol", "alice@example.test", false},
	} {
		if err := operator(step.key, step.typ, step.id, step.externalID, step.userName, step.active); err != nil {
			t.Fatalf("append %s: %v", step.key, err)
		}
	}
	type row struct {
		userName string
		active   bool
	}
	read := func(stage string) map[string]row {
		t.Helper()
		rows, err := st.SystemPool().Query(ctx, `SELECT id, user_name, active FROM provider_operators
			WHERE tenant_id = $1 AND id LIKE 'ls1l2-%' ORDER BY id`, providerAuthorityTenant)
		if err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		defer rows.Close()
		out := map[string]row{}
		for rows.Next() {
			var id string
			var r row
			if err := rows.Scan(&id, &r.userName, &r.active); err != nil {
				t.Fatal(err)
			}
			out[id] = r
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	want := map[string]row{
		"ls1l2-op-alice": {"alice@example.test", true},
		"ls1l2-op-carol": {"carol@example.test", false},
	}
	check := func(stage string) {
		t.Helper()
		got := read(stage)
		if len(got) != len(want) {
			t.Fatalf("%s: operators = %+v, want %+v", stage, got, want)
		}
		for id, w := range want {
			if got[id] != w {
				t.Fatalf("%s: %s = %+v, want %+v", stage, id, got[id], w)
			}
		}
	}
	check("projection")
	truncateProviderAuthority(t, st)
	if err := projections.New(st, projections.WithEventProjection(NewAuthorityProjection(st))).Project(ctx, log); err != nil {
		t.Fatalf("rebuild from the log: %v", err)
	}
	check("rebuild")
}

// TestProviderSCIMUserUnderAHeldUserNameIsRefusedLS1L2: a SCIM user with a
// new externalId under a userName another provider operator holds is a 409
// uniqueness, and nothing is appended; the holder's own update still lands.
func TestProviderSCIMUserUnderAHeldUserNameIsRefusedLS1L2(t *testing.T) {
	t.Parallel()
	access := newAUD58AccessStore()
	mutations := &aud58MutationSink{store: access}
	s := newA221SCIM(t, access, mutations, func() time.Time { return time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC) })
	alice := s.create("okta-alice")
	before := len(mutations.seen)
	rec := s.call(http.MethodPost, "/provider/scim/v2/Users", `{"schemas":["`+scim.SchemaUser+
		`"],"externalId":"okta-alice-2","userName":"okta-alice@example.test","active":true}`)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "uniqueness") {
		t.Fatalf("a new externalId under a held userName = %d %s, want 409 uniqueness", rec.Code, rec.Body.String())
	}
	if len(mutations.seen) != before {
		t.Fatalf("the refused user appended %d events", len(mutations.seen)-before)
	}
	if rec := s.call(http.MethodPut, "/provider/scim/v2/Users/"+alice, `{"schemas":["`+scim.SchemaUser+
		`"],"externalId":"okta-alice","userName":"okta-alice@example.test","displayName":"Alice","active":true}`); rec.Code != http.StatusOK {
		t.Fatalf("the holder's own update = %d %s", rec.Code, rec.Body.String())
	}
}
