// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateIdentityBindingsRequireExactTenantEvidence(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	ownerID := "21800000-0000-4000-8000-000000000001"
	firstID := "21800000-0000-4000-8000-000000000002"
	secondID := "21800000-0000-4000-8000-000000000003"
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "bindings"}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertOwner(ctx, store.Owner{ID: ownerID, TenantID: tenant, Kind: store.OwnerService, Name: "same-owner"}); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{firstID, secondID} {
			if err := s.UpsertIdentity(ctx, store.Identity{ID: id, TenantID: tenant, OwnerID: ownerID, Name: "same.example", Kind: store.KindX509Certificate, Status: "deployed", Attributes: []byte(fmt.Sprintf(`{"deployment_target":%q}`, "target-"+id))}); err != nil {
				t.Fatal(err)
			}
		}
	}
	makeCert := func(key string) store.Certificate {
		t.Helper()
		c, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &ownerID, Subject: "CN=same.example", Fingerprint: "fp-" + key, IssuanceIdempotencyKey: key, Source: "import"})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := makeCert("issue:transition:first")
	renewed := makeCert("renew:transition:renewed")
	unbound := makeCert("unbound")
	delivered := makeCert("delivered")
	legacy := makeCert("issue:legacy")
	var agentJob int64
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		// Other lanes can carry opaque bytes; this reader must not parse them.
		if _, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key) VALUES($1,'unrelated.binary',$2,'opaque')`, tenantA, []byte{0xff, 0x00}); err != nil {
			return err
		}
		for n, key := range []string{"first", "renewed"} {
			event := "identity.issued"
			if n == 1 {
				event = "identity.renewing"
			}
			if err := s.AppendIdentityTransitionTx(ctx, tx, tenantA, store.IdentityTransition{IdentityID: firstID, Seq: uint64(n + 1), FromState: "requested", ToState: "issued", EventType: event, IdempotencyKey: key, OccurredAt: time.Now()}); err != nil {
				return err
			}
		}
		for n, id := range []string{firstID, secondID} {
			_, err := tx.Exec(ctx, `INSERT INTO connector_delivery_receipts (id,tenant_id,identity_id,connector,target,fingerprint,status,created_at,updated_at) VALUES(gen_random_uuid(),$1,$2,'nginx','same-target',$3,$4,now(),now())`, tenantA, id, delivered.Fingerprint, []string{"verified", "failed"}[n])
			if err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key) VALUES($1,'ca.issue',$2,'legacy')`, tenantA, []byte(fmt.Sprintf(`{"identity_id":%q}`, secondID)))
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key,required_agent_role) VALUES($1,'endpoint.renew',$2,'agent-renew','host') RETURNING id`, tenantA, []byte(fmt.Sprintf(`{"identity_id":%q}`, secondID))).Scan(&agentJob)
	}); err != nil {
		t.Fatal(err)
	}
	host := makeCert(fmt.Sprintf("agentcsr:%d:attempt-2", agentJob))
	// Same retained request key and fingerprint in another tenant must not add a binding.
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		return s.AppendIdentityTransitionTx(ctx, tx, tenantB, store.IdentityTransition{IdentityID: secondID, Seq: 1, FromState: "requested", ToState: "issued", EventType: "identity.issued", IdempotencyKey: "first", OccurredAt: time.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	ids := []string{first.ID, renewed.ID, unbound.ID, delivered.ID, legacy.ID, host.ID}
	got, err := s.CertificateIdentityBindings(ctx, tenantA, ids)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{first.ID: {firstID}, renewed.ID: {firstID}, delivered.ID: {firstID}, legacy.ID: {secondID}, host.ID: {secondID}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bindings=%v, want %v", got, want)
	}
	assertCertificateImpactBindings(t, s, tenantA, want, []string{unbound.ID})
	assertCertificateImpactBindings(t, s, tenantB, nil, ids)
	other, err := s.CertificateIdentityBindings(ctx, tenantB, ids)
	if err != nil || len(other) != 0 {
		t.Fatalf("cross-tenant bindings=%v, err=%v", other, err)
	}
	// Real shared delivery stays ambiguous instead of choosing the first name match.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE connector_delivery_receipts SET status='verified' WHERE tenant_id=$1 AND identity_id=$2 AND fingerprint=$3`, tenantA, secondID, delivered.Fingerprint)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err = s.CertificateIdentityBindings(ctx, tenantA, []string{delivered.ID})
	if err != nil || !reflect.DeepEqual(got[delivered.ID], []string{firstID, secondID}) {
		t.Fatalf("shared bindings=%v, err=%v", got, err)
	}
	// Exercise both inventory paging and the binding reader's 1000-ID cap.
	// These same-owner records have no binding and must stay unrelated.
	for n := 0; n < 1001; n++ {
		makeCert(fmt.Sprintf("unbound-page-%04d", n))
	}
	want[delivered.ID] = []string{firstID, secondID}
	assertCertificateImpactBindings(t, s, tenantA, want, []string{unbound.ID})
	if _, err := s.CertificateIdentityBindings(context.Background(), tenantA, make([]string, 1001)); err == nil {
		t.Fatal("unbounded page accepted")
	}
}

// A certificate reaches only its exact retained identities and their declared
// destinations. Shared names/owners and another tenant cannot manufacture links.
func assertCertificateImpactBindings(t *testing.T, s *store.Store, tenant string, bindings map[string][]string, unbound []string) {
	t.Helper()
	g, err := graph.Build(t.Context(), s, tenant)
	if err != nil {
		t.Fatal(err)
	}
	for certificate, identities := range bindings {
		got := map[string]bool{}
		for _, node := range g.BlastRadius("cert:" + certificate).Affected {
			got[node.ID] = true
		}
		expected := map[string]bool{}
		for _, identity := range identities {
			expected["id:"+identity] = true
			expected["res:target-"+identity] = true
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("certificate %s impact = %v, want exact identity and target %v", certificate, got, expected)
		}
		for _, edge := range g.Edges() {
			if edge.From == "cert:"+certificate && edge.Type == graph.EdgeType("BOUND_TO_IDENTITY") && (edge.Confidence != "authoritative" || edge.Source == "") {
				t.Fatalf("binding lacks its authority: %+v", edge)
			}
		}
	}
	for _, certificate := range unbound {
		if got := g.BlastRadius("cert:" + certificate); len(got.Affected) != 0 {
			t.Fatalf("unbound or foreign certificate gained impact: %+v", got)
		}
	}
}
