package whitelabel

import (
	"context"
	"html/template"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/branding"
)

func seededResolver(t *testing.T) (*MemStore, *Resolver) {
	t.Helper()
	store := NewMemStore()
	ctx := context.Background()
	if err := store.SetProviderBrand(ctx, Record{
		ProductName:   "TrustOps MSP",
		EmailFooter:   "Sent by TrustOps",
		EmailFromName: "TrustOps Alerts",
		TokenOverrides: map[string]string{
			"--color-accent": "#315a9f",
			"--color-focus":  "#315a9f",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTenantBrand(ctx, Record{
		TenantID:      "tenant-a",
		ProductName:   "Acme Trust",
		LoginMessage:  "Welcome to Acme Trust",
		CustomDomain:  "Login.Acme.example:443",
		EmailFromName: "Acme Trust Alerts",
		TokenOverrides: map[string]string{
			"--color-accent": "#c2410c",
		},
	}); err != nil {
		t.Fatal(err)
	}
	return store, NewResolver(store, time.Minute)
}

func TestResolverCacheNeverBleedsAcrossTenantOrHost(t *testing.T) {
	store, resolver := seededResolver(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		a := resolver.Resolve(ctx, "", "tenant-a")
		b := resolver.Resolve(ctx, "", "tenant-b")
		if a.ProductName != "Acme Trust" || a.LoginMessage != "Welcome to Acme Trust" {
			t.Fatalf("tenant-a brand = %+v", a)
		}
		if b.ProductName != "TrustOps MSP" || b.LoginMessage != "" {
			t.Fatalf("tenant-b should receive only provider master/default fields: %+v", b)
		}
		if b.TokenOverrides["--color-accent"] == "#c2410c" {
			t.Fatalf("tenant-a token bled into tenant-b: %+v", b.TokenOverrides)
		}
	}

	store.FailAll(true)
	fresh := NewResolver(store, time.Minute)
	if got := fresh.Resolve(ctx, "", "tenant-b"); got.ProductName != "trstctl" || got.TokenOverrides != nil {
		t.Fatalf("store failure must degrade to default brand, never cached tenant/master: %+v", got)
	}
	if tenant := resolver.TenantForHost(ctx, "login.other.example"); tenant != "" {
		t.Fatalf("unknown host mapped to tenant %q", tenant)
	}
}

func TestCustomDomainLoginResolvesTenantBrand(t *testing.T) {
	_, resolver := seededResolver(t)
	ctx := context.Background()

	if tenant := resolver.TenantForHost(ctx, "login.acme.example"); tenant != "tenant-a" {
		t.Fatalf("custom-domain tenant = %q, want tenant-a", tenant)
	}
	if tenant := resolver.TenantForHost(ctx, "LOGIN.ACME.EXAMPLE:443."); tenant != "tenant-a" {
		t.Fatalf("normalized custom-domain tenant = %q, want tenant-a", tenant)
	}
	if got := resolver.Resolve(ctx, "login.acme.example", ""); got.ProductName != "Acme Trust" {
		t.Fatalf("custom-domain brand = %+v", got)
	}
	if got := resolver.Resolve(ctx, "login.acme.example", "tenant-b"); got.ProductName != "TrustOps MSP" {
		t.Fatalf("explicit signed-in tenant must beat host brand: %+v", got)
	}
}

func TestBrandedEmailUsesResolvedBrandAndEscapesFields(t *testing.T) {
	_, resolver := seededResolver(t)
	brand := resolver.Resolve(context.Background(), "", "tenant-a")
	html, from, err := RenderEmail(brand, Email{
		Subject:   "Certificate expiring",
		Preheader: "One certificate expires soon",
		BodyHTML:  template.HTML("<p>Rotate <strong>api.acme.example</strong></p>"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Acme Trust", "Certificate expiring", "Rotate <strong>api.acme.example</strong>", "Sent by TrustOps"} {
		if !strings.Contains(html, want) {
			t.Fatalf("email missing %q:\n%s", want, html)
		}
	}
	if from != "Acme Trust Alerts" {
		t.Fatalf("from = %q, want Acme Trust Alerts", from)
	}

	hostile := branding.Brand{ProductName: `<script>alert(1)</script>`}
	html, from, err = RenderEmail(hostile, Email{Subject: "x", BodyHTML: template.HTML("<p>ok</p>")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<script>") {
		t.Fatal("brand fields must be escaped in email HTML")
	}
	if from != hostile.ProductName {
		t.Fatalf("from fallback = %q, want raw display name for mail layer", from)
	}
}
