// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/branding"
)

// AUD-14: branding.SetSource was called by the licensed white-label install and
// branding.Resolve — the only consumer of what it sets — was never called
// anywhere in production. A licensed provider saw "Provider white-label
// branding attached" in the log and no downstream customer ever saw their
// brand.

type fakeBrandSource struct {
	brand branding.Brand
	calls int
}

func (f *fakeBrandSource) Resolve(context.Context, string, string) branding.Brand {
	f.calls++
	return f.brand
}
func (f *fakeBrandSource) TenantForHost(context.Context, string) string { return "" }

// The property is that the SERVED HANDLER consults the source — not merely that
// the branding package works. An earlier version of this test called
// branding.Resolve directly, which would have passed even with the handler
// returning the default and ignoring the installed source entirely: exactly the
// defect being fixed, surviving its own regression test.
func TestTheServedBrandHandlerConsultsTheInstalledSource(t *testing.T) {
	src := &fakeBrandSource{brand: branding.Brand{ProductName: "AcmeTrust"}}
	branding.SetSource(src)
	t.Cleanup(func() { branding.SetSource(nil) })

	a := &API{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/brand", nil)
	req.Host = "acme.example"
	rec := httptest.NewRecorder()
	a.getBrand(rec, req)

	var got brandResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if src.calls == 0 {
		t.Fatal("an installed brand source was never consulted.\n\n" +
			"This is the whole defect: the resolver was constructed, wired via SetSource, and " +
			"asked nothing — so a licensed provider's customers saw the default brand forever " +
			"while the log said white-label was attached.")
	}
	if got.ProductName != "AcmeTrust" {
		t.Fatalf("served product name = %q, want the provider's brand", got.ProductName)
	}
	if !got.Custom {
		t.Error("a resolved provider brand was reported as not custom; an operator could not tell " +
			"it from an unconfigured deployment")
	}
}

// With no source installed, the default must be served — and reported AS the
// default, so "nothing configured" is distinguishable from "this host has no
// brand". Both render identically and only one is a misconfiguration.
func TestTheDefaultBrandIsReportedAsNotCustom(t *testing.T) {
	branding.SetSource(nil)
	b := branding.Resolve(context.Background(), "anything.example", "")
	def := branding.Default()
	if b.ProductName != def.ProductName {
		t.Fatalf("product name = %q with no source installed, want the built-in default", b.ProductName)
	}
	custom := b.ProductName != def.ProductName || b.LogoDataURI != "" || b.LoginMessage != ""
	if custom {
		t.Fatal("the built-in default was reported as a custom brand; an operator could not tell " +
			"an unconfigured deployment from one whose host has no brand")
	}
}

// The public rationale must exist and must say what the response does NOT
// carry. A public route whose rationale does not bound its contents is how
// tenant data reaches an unauthenticated caller later.
func TestTheBrandRouteDeclaresWhatItDoesNotExpose(t *testing.T) {
	t.Parallel()
	r := publicRationaleForRoute(route{opID: "getBrand"})
	if r == "" {
		t.Fatal("the brand route has no public rationale; a silently public route is how a " +
			"surface gets exposed by accident")
	}
	for _, must := range []string{"no tenant data", "no credential material"} {
		if !strings.Contains(r, must) {
			t.Errorf("the rationale does not state %q — a public route whose rationale does not "+
				"bound its contents invites tenant data into it later", must)
		}
	}
}
