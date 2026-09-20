// SPDX-License-Identifier: BUSL-1.1

package idemgc_test

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/idemgc"
	"trstctl.com/trstctl/internal/store"
)

func TestUnfinishedLeafDeliveryRetainsPreparationAcrossSweep(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenantB = "22222222-2222-4222-8222-222222222222"
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "leaf retention QA"}); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().UTC().Add(-8 * 24 * time.Hour)
	slot := strings.Repeat("a", 64) + ":"
	for _, status := range []string{"pending", "processing", "failed", "delivered"} {
		for _, prefix := range []string{"leaf-template:v1:", "leaf-subject:v1:"} {
			seedCompleted(t, s, prefix+slot+status, old)
		}
		if _, err := s.SystemPool().Exec(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status) VALUES ($1, 'ca.issue', $2, $3, $3)`, tenantA, []byte(`{}`), status); err != nil {
			t.Fatal(err)
		}
	}
	seedCompleted(t, s, "ordinary-old", old)
	seedCompleted(t, s, "leaf-template:v1:"+slot+"other-tenant-only", old)
	if _, err := s.SystemPool().Exec(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status) VALUES ($1, 'ca.issue', $2, 'other-tenant-only', 'failed')`, tenantB, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	removed, err := idemgc.New(s, 24*time.Hour).Sweep(ctx)
	if err != nil || removed != 4 {
		t.Fatalf("sweep removed=%d err=%v, want delivered pair plus ordinary and other-tenant records", removed, err)
	}
	// Finishing those exact commands releases the six protected preparations.
	if _, err := s.SystemPool().Exec(ctx, `UPDATE outbox SET status = 'delivered' WHERE tenant_id = $1`, tenantA); err != nil {
		t.Fatal(err)
	}
	removed, err = idemgc.New(s, 24*time.Hour).Sweep(ctx)
	if err != nil || removed != 6 {
		t.Fatalf("completed sweep removed=%d err=%v, want six", removed, err)
	}
}
