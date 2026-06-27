package branding

import (
	"context"
	"testing"
)

type fakeSource struct {
	byHost map[string]string
}

func (f fakeSource) Resolve(_ context.Context, host, tenantID string) Brand {
	if tenantID == "tenant-a" || f.byHost[host] == "tenant-a" {
		return Brand{ProductName: "Acme Trust"}
	}
	return Default()
}

func (f fakeSource) TenantForHost(_ context.Context, host string) string {
	return f.byHost[host]
}

func TestBrandingDefaultIsBuiltIn(t *testing.T) {
	SetSource(nil)

	if got := Resolve(context.Background(), "login.example", "tenant-a"); got.ProductName != "trstctl" {
		t.Fatalf("default brand = %+v", got)
	}
	if got := TenantForHost(context.Background(), "login.example"); got != "" {
		t.Fatalf("default host mapping = %q, want empty", got)
	}
}

func TestBrandingSourceSetterHooksFire(t *testing.T) {
	SetSource(nil)
	t.Cleanup(func() { SetSource(nil) })

	SetSource(fakeSource{byHost: map[string]string{"trust.acme.example": "tenant-a"}})
	if got := Resolve(context.Background(), "", "tenant-a"); got.ProductName != "Acme Trust" {
		t.Fatalf("tenant brand = %+v", got)
	}
	if got := TenantForHost(context.Background(), "trust.acme.example"); got != "tenant-a" {
		t.Fatalf("host tenant = %q", got)
	}
	if got := Resolve(context.Background(), "other.example", "tenant-b"); got.ProductName != "trstctl" {
		t.Fatalf("brand bled across tenants: %+v", got)
	}
}
