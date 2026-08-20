// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestWorkloadAttesterProjectionReplayConvergesOnThePrimaryKey(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	apply := func(tenantID string, candidate store.WorkloadAttesterTrustSource) error {
		return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.ApplyWorkloadAttesterTrustSourceUpsertedTx(ctx, tx, candidate)
		})
	}
	var row store.WorkloadAttesterTrustSource
	for i := 0; i < 24; i++ {
		row = store.WorkloadAttesterTrustSource{
			ID: fmt.Sprintf("a8e0cded-3832-4112-8702-%012x", i), TenantID: tenantA,
			Name: fmt.Sprintf("qa-k8s-%02d", i), Method: "k8s_sat", Issuer: "https://cluster.invalid",
			Audience: "trstctl", JWKS: json.RawMessage(`{"keys":[]}`), Enabled: true,
			RotationVersion: 1, CreatedAt: now, UpdatedAt: now,
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		for range 2 {
			go func(candidate store.WorkloadAttesterTrustSource) {
				defer wg.Done()
				<-start
				errs <- apply(tenantA, candidate)
			}(row)
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent same-event projection %d hit a uniqueness boundary: %v", i, err)
			}
		}
		if err := apply(tenantA, row); err != nil {
			t.Fatalf("sequential same-event replay %d did not converge: %v", i, err)
		}
	}

	crossTenant := row
	crossTenant.TenantID = tenantB
	crossTenant.Name = "tenant-b-collision"
	if err := apply(tenantB, crossTenant); !errors.Is(err, store.ErrWorkloadAttesterTrustSourceTenantCollision) {
		t.Fatalf("cross-tenant primary-key collision = %v, want fail-closed tenant collision", err)
	}
	got, err := s.GetWorkloadAttesterTrustSource(ctx, tenantA, row.ID)
	if err != nil || got.Name != row.Name || got.TenantID != tenantA {
		t.Fatalf("cross-tenant collision changed the original row: got=%+v err=%v", got, err)
	}
}
