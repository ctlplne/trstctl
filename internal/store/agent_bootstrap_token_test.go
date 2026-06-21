package store_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestBootstrapTokenRedeemIsMarkedSystemQueryAndSingleUse(t *testing.T) {
	src, err := os.ReadFile("agent_bootstrap_token.go")
	if err != nil {
		t.Fatalf("read agent_bootstrap_token.go: %v", err)
	}
	if !strings.Contains(string(src), "//trstctl:system-query") ||
		!strings.Contains(string(src), "UPDATE agent_bootstrap_tokens") ||
		!strings.Contains(string(src), "globally-unique, high-entropy one-time token hash") {
		t.Fatal("RedeemBootstrapToken must carry a precise //trstctl:system-query marker for its pre-tenant RLS bypass")
	}

	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	token, err := s.CreateBootstrapToken(ctx, store.BootstrapTokenRecord{
		TenantID:        tenantA,
		TokenHash:       "sha256:bootstrap-a",
		AllowedIdentity: "agent-a",
		ExpiresAt:       time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateBootstrapToken: %v", err)
	}
	if token.ID == "" || token.CreatedAt.IsZero() {
		t.Fatalf("CreateBootstrapToken returned incomplete record: %+v", token)
	}

	redeemed, err := s.RedeemBootstrapToken(ctx, "sha256:bootstrap-a")
	if err != nil {
		t.Fatalf("RedeemBootstrapToken: %v", err)
	}
	if redeemed.TenantID != tenantA {
		t.Fatalf("RedeemBootstrapToken tenant = %q, want %q", redeemed.TenantID, tenantA)
	}
	if redeemed.AllowedIdentity != "agent-a" {
		t.Fatalf("RedeemBootstrapToken allowed identity = %q, want agent-a", redeemed.AllowedIdentity)
	}
	if redeemed.UsedAt == nil {
		t.Fatal("RedeemBootstrapToken did not stamp used_at")
	}

	if _, err := s.RedeemBootstrapToken(ctx, "sha256:bootstrap-a"); !store.IsNotFound(err) {
		t.Fatalf("second RedeemBootstrapToken = %v, want not found", err)
	}
}

func TestRedeemBootstrapTokenConsumesOnce(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	if _, err := s.CreateBootstrapToken(ctx, store.BootstrapTokenRecord{
		TenantID:        tenantA,
		TokenHash:       "sha256:consume-once",
		AllowedIdentity: "edge-agent",
		ExpiresAt:       time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateBootstrapToken: %v", err)
	}

	first, err := s.RedeemBootstrapToken(ctx, "sha256:consume-once")
	if err != nil {
		t.Fatalf("first RedeemBootstrapToken: %v", err)
	}
	if first.TenantID != tenantA {
		t.Fatalf("first RedeemBootstrapToken tenant = %q, want %q", first.TenantID, tenantA)
	}
	if first.AllowedIdentity != "edge-agent" {
		t.Fatalf("first RedeemBootstrapToken allowed identity = %q, want edge-agent", first.AllowedIdentity)
	}
	if first.UsedAt == nil {
		t.Fatal("first RedeemBootstrapToken did not stamp used_at")
	}

	if _, err := s.RedeemBootstrapToken(ctx, "sha256:consume-once"); !store.IsNotFound(err) {
		t.Fatalf("replayed RedeemBootstrapToken = %v, want not found", err)
	}
}
