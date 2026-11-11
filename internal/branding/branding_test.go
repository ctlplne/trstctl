// SPDX-License-Identifier: BUSL-1.1

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

// MSP-1: one rule says when a brand is a white-label brand, so every surface
// agrees on when to show "Powered by trstctl". Any field that differs from the
// built-in brand makes it custom, including a brand that changes only colors or
// only the email strings; blank fields do not.
func TestIsCustomCoversEveryBrandFieldMSP1(t *testing.T) {
	if IsCustom(Default()) || IsCustom(Brand{}) || IsCustom(Brand{ProductName: " trstctl ", LoginMessage: "  ", EmailFooter: "\t"}) {
		t.Fatal("the built-in brand, or one with only blank fields, was reported custom")
	}
	for name, b := range map[string]Brand{
		"product name":    {ProductName: "Northwind Managed PKI"},
		"logo":            {LogoDataURI: "data:image/png;base64,iVBORw0KGgo="},
		"login message":   {LoginMessage: "Northwind customers sign in here."},
		"token overrides": {TokenOverrides: map[string]string{"--foreground": "0 0% 100%"}},
		"email from name": {EmailFromName: "Northwind Alerts"},
		"email footer":    {EmailFooter: "Northwind Managed PKI"},
	} {
		if !IsCustom(b) {
			t.Errorf("a brand that sets only its %s was not reported custom", name)
		}
	}
	SetSource(fakeSource{})
	t.Cleanup(func() { SetSource(nil) })
	if got := PoweredByLine(context.Background(), "tenant-a"); got != "Powered by trstctl" {
		t.Fatalf("a white-labeled tenant's line = %q", got)
	}
	if got := PoweredByLine(context.Background(), "tenant-b"); got != "" {
		t.Fatalf("a tenant on the built-in brand got the line %q", got)
	}
}
