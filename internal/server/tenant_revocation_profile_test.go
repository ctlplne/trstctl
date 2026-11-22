// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"reflect"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/profile"
)

// A deployment-wide pointer that names the platform CA's tenant route must
// be rebound before any other tenant's leaf is signed. An external responder
// URL does not identify a trstctl tenant route and stays operator-owned.
func TestPlatformProtocolProfileBindsRevocationRoutesToIssuingTenantCR069(t *testing.T) {
	const pointerTenant = "11111111-1111-1111-1111-111111111111"
	const issuingTenant = "88888888-8888-4888-8888-888888888888"
	p := &protocolIssuer{leafProfile: crypto.LeafProfile{
		CRLDistributionPoints: []string{
			"https://cp.example.test/crl/" + pointerTenant,
			"https://external.example.test/issuer-wide.crl",
		},
		OCSPServers: []string{"https://cp.example.test/ocsp/" + pointerTenant},
	}}
	profile, _, err := p.enforceProfile(context.Background(), issuingTenant, "acme", "", crypto.CSRInfo{}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wantCRL := []string{"https://cp.example.test/crl/" + issuingTenant, "https://external.example.test/issuer-wide.crl"}
	if !reflect.DeepEqual(profile.CRLDistributionPoints, wantCRL) {
		t.Fatalf("leaf CDPs = %v, want tenant-bound %v", profile.CRLDistributionPoints, wantCRL)
	}
	wantOCSP := []string{"https://cp.example.test/ocsp/" + issuingTenant}
	if !reflect.DeepEqual(profile.OCSPServers, wantOCSP) {
		t.Fatalf("leaf OCSP AIA = %v, want tenant-bound %v", profile.OCSPServers, wantOCSP)
	}
	if p.leafProfile.CRLDistributionPoints[0] != "https://cp.example.test/crl/"+pointerTenant {
		t.Fatal("tenant binding mutated the shared deployment profile")
	}
}

func TestConfiguredTenantRevocationURLTemplatesCR069(t *testing.T) {
	const tenant = "88888888-8888-4888-8888-888888888888"
	for _, tc := range []struct{ raw, kind, want string }{
		{"https://cp.example.test/crl/{tenant_id}", "crl", "https://cp.example.test/crl/" + tenant},
		{"https://cp.example.test/crl/{tenant_id}.crl", "crl", "https://cp.example.test/crl/" + tenant + ".crl"},
		{"https://cp.example.test/ocsp/{tenant_id}", "ocsp", "https://cp.example.test/ocsp/" + tenant},
		{"https://external.example.test/status/issuer-wide", "ocsp", "https://external.example.test/status/issuer-wide"},
	} {
		if got := tenantBoundRevocationURL(tc.raw, tc.kind, tenant); got != tc.want {
			t.Errorf("bind %q = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// The public per-tenant CRL must still have a tenant-distinct signed scope
// when leaves use an external issuer-wide responder or have no automatic CDP.
// Otherwise one tenant's CRL can be replayed as another's complete list.
func TestPlatformCRLScopeStaysTenantDistinctWithoutTenantCDPCR069(t *testing.T) {
	const otherTenant = "88888888-8888-4888-8888-888888888888"
	for _, cdps := range [][]string{nil, {"https://external.example.test/issuer-wide.crl"}} {
		h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
			d.LeafProfile = crypto.LeafProfile{CRLDistributionPoints: cdps}
		})
		for _, tenantID := range []string{servedTestTenant, otherTenant} {
			got := h.srv.revoc.fullCRLURLs(tenantID)
			want := []string{"urn:trstctl:tenant-crl:" + tenantID}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("tenant %s CRL scope with CDPs %v = %v, want %v", tenantID, cdps, got, want)
			}
		}
	}
}

func TestPlatformCRLScopeOmitsIssuerWideExternalCDPWhenTenantRouteExistsCR069(t *testing.T) {
	const tenantID = "88888888-8888-4888-8888-888888888888"
	profile := crypto.LeafProfile{CRLDistributionPoints: []string{
		"https://cp.example.test/crl/11111111-1111-1111-1111-111111111111",
		"https://external.example.test/issuer-wide.crl",
	}}
	want := []string{"https://cp.example.test/crl/" + tenantID}
	if got := platformFullCRLScopes(profile, tenantID); !reflect.DeepEqual(got, want) {
		t.Fatalf("tenant CRL signed scopes = %v, want %v", got, want)
	}
}

// A private or upstream issuer controls its own revocation publisher. The
// platform's tenant-route rewrite must not silently change that CA's pointer.
func TestNonPlatformIssuersKeepConfiguredRevocationPointersCR069(t *testing.T) {
	const configuredTenant = "11111111-1111-4111-8111-111111111111"
	h := newOperatingServedHarness(t, config.Protocols{})
	storeServerTestProfile(t, h.store, h.tenant, "cr069-operator-ca", profile.CertificateProfile{Name: "cr069-operator-ca"})
	base := crypto.LeafProfile{
		CRLDistributionPoints: []string{"https://issuer.example.test/crl/" + configuredTenant},
		OCSPServers:           []string{"https://issuer.example.test/ocsp/" + configuredTenant},
	}
	for _, selected := range []string{"", "cr069-operator-ca"} {
		d := &issuanceDispatcher{store: h.store, leafProfile: base, defaultProfile: selected}
		for _, authority := range []string{"private", "external"} {
			got, err := d.enforceProfileForPurpose(context.Background(), h.tenant, authority,
				ekuCSR(t, "operator-ca.example.test"), []string{"operator-ca.example.test"}, time.Hour, "api")
			if err != nil {
				t.Fatalf("%s profile %q: %v", authority, selected, err)
			}
			if !reflect.DeepEqual(got.CRLDistributionPoints, base.CRLDistributionPoints) ||
				!reflect.DeepEqual(got.OCSPServers, base.OCSPServers) {
				t.Errorf("%s CA profile %q changed revocation pointers: CDP %v, OCSP %v", authority, selected, got.CRLDistributionPoints, got.OCSPServers)
			}
		}
	}
}
