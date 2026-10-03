// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/xml"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func TestServiceProviderLookupUsesExactEntityAndPinnedMetadata(t *testing.T) {
	const entityID = "https://127.0.0.1:9443/auth/saml/metadata"
	metadataURL, err := url.Parse(entityID)
	if err != nil {
		t.Fatal(err)
	}
	acsURL, err := url.Parse("https://127.0.0.1:9443/auth/saml/acs")
	if err != nil {
		t.Fatal(err)
	}
	sp := &saml.ServiceProvider{EntityID: entityID, MetadataURL: *metadataURL, AcsURL: *acsURL}
	raw, err := xml.Marshal(sp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "sp.xml")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	idp := &labIDP{spEntityID: entityID, spMetadata: file}
	request := httptest.NewRequest("GET", "/sso", nil)
	if _, err := idp.GetServiceProvider(request, "https://unregistered.example/sp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unregistered SP = %v, want not found", err)
	}
	got, err := idp.GetServiceProvider(request, entityID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EntityID != entityID || len(got.SPSSODescriptors) != 1 {
		t.Fatalf("loaded SP metadata = %+v, want exact entity and one SP descriptor", got)
	}
	if err := os.WriteFile(file, []byte("not XML"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := idp.GetServiceProvider(request, entityID); err == nil {
		t.Fatal("malformed pinned metadata unexpectedly accepted")
	}
}

func TestSessionUsesFreshAssertionWindow(t *testing.T) {
	old := time.Now().Add(-24 * time.Hour)
	idp := &labIDP{session: &saml.Session{ID: "qa", NameID: "qa@local", CreateTime: old, ExpireTime: old.Add(time.Hour)}}
	got := idp.GetSession(nil, nil, nil)
	if got.ID != "qa" || got.NameID != "qa@local" {
		t.Fatalf("identity changed: %+v", got)
	}
	if time.Since(got.CreateTime) > time.Minute || got.ExpireTime.Sub(got.CreateTime) != time.Hour {
		t.Fatalf("assertion window was not refreshed: %+v", got)
	}
	if idp.session.CreateTime != old {
		t.Fatal("shared session template was mutated")
	}
}

func TestLabAttributesRequireUniqueNonReservedNames(t *testing.T) {
	var attributes labAttributes
	if err := attributes.Set("groups=provider-admin"); err != nil {
		t.Fatal(err)
	}
	if err := attributes.Set("amr=mfa"); err != nil {
		t.Fatal(err)
	}
	got := attributes.SAML()
	if len(got) != 2 || got[0].Name != "groups" || got[0].Values[0].Value != "provider-admin" || got[1].Name != "amr" || got[1].Values[0].Value != "mfa" {
		t.Fatalf("claims = %+v", got)
	}
	for _, invalid := range []string{"groups=other", "email=other@local.qa", "tenant=other", "bad name=value", "amr=", "no-equals"} {
		if err := attributes.Set(invalid); err == nil {
			t.Fatalf("accepted invalid lab attribute %q", invalid)
		}
	}
}
