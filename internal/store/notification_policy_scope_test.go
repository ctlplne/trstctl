// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestEffectiveNotificationRoutingPolicyUsesMostSpecificTenantRule(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 24, 9, 40, 0, 0, time.UTC)
	policies := []store.NotificationRoutingPolicy{
		{ID: "00000000-0000-0000-0000-00000000a101", TenantID: tenantA, Name: "Global fallback", ScopeKind: "global", DefaultChannels: []string{"email"}},
		{ID: "00000000-0000-0000-0000-00000000a102", TenantID: tenantA, Name: "Certificate workspace", ScopeKind: "workspace", ScopeRef: "certificate-lifecycle", DefaultChannels: []string{"slack"}},
		{ID: "00000000-0000-0000-0000-00000000a103", TenantID: tenantA, Name: "Platform owner", ScopeKind: "owner", ScopeRef: "owner/platform", DefaultChannels: []string{"pagerduty"}},
		{ID: "00000000-0000-0000-0000-00000000a104", TenantID: tenantA, Name: "Payments leaf", ScopeKind: "asset", ScopeRef: "certificate/cert-payments", DefaultChannels: []string{"opsgenie"}},
	}
	for index := range policies {
		policies[index].CreatedAt = now.Add(time.Duration(index) * time.Second)
		policies[index].UpdatedAt = policies[index].CreatedAt
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyNotificationRoutingPolicyUpsertedTx(ctx, tx, policies[index])
		}); err != nil {
			t.Fatalf("project policy %q: %v", policies[index].Name, err)
		}
	}

	selector := store.NotificationRoutingSelector{
		Workspace: "certificate-lifecycle",
		OwnerRef:  "owner/platform",
		AssetRef:  "certificate/cert-payments",
	}
	got, ok, err := s.ResolveEffectiveNotificationRoutingPolicy(ctx, tenantA, selector)
	if err != nil || !ok || got.ScopeKind != "asset" || got.ID != policies[3].ID {
		t.Fatalf("asset resolution = %+v ok=%t err=%v", got, ok, err)
	}

	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.DeleteNotificationRoutingPolicyTx(ctx, tx, tenantA, policies[3].ID)
	}); err != nil {
		t.Fatal(err)
	}
	got, ok, err = s.ResolveEffectiveNotificationRoutingPolicy(ctx, tenantA, selector)
	if err != nil || !ok || got.ScopeKind != "owner" || got.ID != policies[2].ID {
		t.Fatalf("owner fallback = %+v ok=%t err=%v", got, ok, err)
	}

	selector.OwnerRef = "owner/other"
	got, ok, err = s.ResolveEffectiveNotificationRoutingPolicy(ctx, tenantA, selector)
	if err != nil || !ok || got.ScopeKind != "workspace" || got.ID != policies[1].ID {
		t.Fatalf("workspace fallback = %+v ok=%t err=%v", got, ok, err)
	}

	selector.Workspace = "secrets-access"
	got, ok, err = s.ResolveEffectiveNotificationRoutingPolicy(ctx, tenantA, selector)
	if err != nil || !ok || got.ScopeKind != "global" || got.ID != policies[0].ID {
		t.Fatalf("global fallback = %+v ok=%t err=%v", got, ok, err)
	}

	if _, ok, err := s.ResolveEffectiveNotificationRoutingPolicy(ctx, tenantB, selector); err != nil || ok {
		t.Fatalf("neighbor tenant resolution ok=%t err=%v, want no policy", ok, err)
	}
}
