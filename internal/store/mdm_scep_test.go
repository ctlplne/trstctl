// SPDX-License-Identifier: BUSL-1.1

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

func TestMDMSCEPPolicyProjectionReplayConvergesOnThePrimaryKey(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	apply := func(tenantID string, candidate store.MDMSCEPPolicy) error {
		return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.ApplyMDMSCEPPolicyUpsertedTx(ctx, tx, candidate)
		})
	}

	var row store.MDMSCEPPolicy
	for i := 0; i < 24; i++ {
		row = store.MDMSCEPPolicy{
			ID: fmt.Sprintf("b9f0deed-4832-4112-8702-%012x", i), TenantID: tenantA,
			Name: fmt.Sprintf("qa-intune-%02d", i), Provider: "intune",
			SCEPProfile: "workstation-tls", SCEPEndpoint: "/scep/pkiclient.exe",
			ExpectedAudience: "trstctl-qa", ChallengeMode: "intune-jws",
			TrustAnchorRefs: json.RawMessage(`{"intune_jwks_ref":"secret://mdm/intune-jwks"}`),
			ProfileGuidance: json.RawMessage(`{"platform":"Windows"}`), Enabled: true,
			RotationVersion: 1, CreatedAt: now, UpdatedAt: now,
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		for range 2 {
			go func(candidate store.MDMSCEPPolicy) {
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
	if err := apply(tenantB, crossTenant); !errors.Is(err, store.ErrMDMSCEPPolicyTenantCollision) {
		t.Fatalf("cross-tenant primary-key collision = %v, want fail-closed tenant collision", err)
	}
	got, err := s.GetMDMSCEPPolicy(ctx, tenantA, row.ID)
	if err != nil || got.Name != row.Name || got.TenantID != tenantA {
		t.Fatalf("cross-tenant collision changed the original row: got=%+v err=%v", got, err)
	}
}

func TestMDMSCEPNonceFenceSurvivesRestartAndSerializesHosts(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	other, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	expires := time.Now().UTC().Add(10 * time.Minute)
	start := make(chan struct{})
	results := make(chan bool, 2)
	errors := make(chan error, 2)
	for _, candidate := range []*store.Store{s, other} {
		go func(candidate *store.Store) {
			<-start
			claimed, err := candidate.ConsumeMDMSCEPNonce(ctx, tenantA, "one-time-local-jws-nonce", expires)
			results <- claimed
			errors <- err
		}(candidate)
	}
	close(start)
	claimedCount := 0
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
		if <-results {
			claimedCount++
		}
	}
	if claimedCount != 1 {
		t.Fatalf("concurrent control planes claimed the same signed nonce %d times, want one", claimedCount)
	}
	if claimed, err := other.ConsumeMDMSCEPNonce(ctx, tenantA, "one-time-local-jws-nonce", expires); err != nil || claimed {
		t.Fatalf("cold control plane reused consumed nonce: claimed=%t err=%v", claimed, err)
	}
	if claimed, err := other.ConsumeMDMSCEPNonce(ctx, tenantB, "one-time-local-jws-nonce", expires); err != nil || !claimed {
		t.Fatalf("tenant-scoped nonce was incorrectly shared: claimed=%t err=%v", claimed, err)
	}
}
