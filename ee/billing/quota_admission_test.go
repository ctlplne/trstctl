// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/usage"
)

func TestQuotaAdmissionSeesNewCapImmediatelyAndFailsClosedOnCountError(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	checker := NewQuotaChecker(store, func(context.Context, string) (TenantCounts, error) {
		return TenantCounts{usage.MeterAgents: 0}, nil
	}, time.Minute)
	if err := checker.AllowCreate(ctx, "tenant-a", usage.MeterAgents); err != nil {
		t.Fatal(err)
	}
	zero := 0
	if err := store.SetQuota(ctx, Quota{TenantID: "tenant-a", MaxAgents: &zero}); err != nil {
		t.Fatal(err)
	}
	if err := checker.AllowCreate(ctx, "tenant-a", usage.MeterAgents); !errors.Is(err, usage.ErrQuotaExhausted) {
		t.Fatalf("updated zero cap = %v, want immediate refusal", err)
	}
	broken := NewQuotaChecker(store, func(context.Context, string) (TenantCounts, error) {
		return nil, errors.New("count unavailable")
	}, time.Minute)
	if err := broken.AllowCreate(ctx, "tenant-a", usage.MeterAgents); !errors.Is(err, usage.ErrQuotaUnavailable) {
		t.Fatalf("count outage = %v, want retryable quota-authority refusal", err)
	}
	missingStore := NewQuotaChecker(&PGStore{}, nil, time.Minute)
	if err := missingStore.AllowCreate(ctx, "tenant-a", usage.MeterAgents); !errors.Is(err, usage.ErrQuotaUnavailable) {
		t.Fatalf("durable quota-store outage = %v, want retryable quota-authority refusal", err)
	}
	if _, err := StoreTenantCounter(nil)(ctx, "tenant-a"); err == nil {
		t.Fatal("missing resource counter silently reported zero resources")
	}
}
