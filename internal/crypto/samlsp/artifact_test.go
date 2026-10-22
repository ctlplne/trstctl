// SPDX-License-Identifier: BUSL-1.1

package samlsp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"

	"trstctl.com/trstctl/internal/crypto/samltest"
)

func artifactIdPMetadata(t *testing.T, withResolver bool) string {
	t.Helper()
	key, cert, err := samltest.NewIdentityProviderMaterial("a76-idp")
	if err != nil {
		t.Fatalf("generate IdP material: %v", err)
	}
	idp := saml.IdentityProvider{Certificate: cert, Key: key,
		MetadataURL: mustAUD58URL(t, "https://idp.example.test/metadata"), SSOURL: mustAUD58URL(t, "https://idp.example.test/sso")}
	descriptor := idp.Metadata()
	if withResolver {
		descriptor.IDPSSODescriptors[0].ArtifactResolutionServices = []saml.Endpoint{{
			Binding: saml.SOAPBinding, Location: "https://idp.example.test/artifact"}}
	}
	metadata, err := xml.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return string(metadata)
}

func artifactConfig(metadata string) Config {
	return Config{
		EntityID: "https://app.example.test/auth/saml/metadata", MetadataURL: "https://app.example.test/auth/saml/metadata",
		ACSURL: "https://app.example.test/auth/saml/acs", IDPMetadataXML: metadata,
		ResponseBinding:     ResponseBindingArtifact,
		NewArtifactResolver: func(string) (*http.Client, error) { return &http.Client{}, nil },
	}
}

// A76: the artifact binding fails closed at construction when the IdP declares
// no SOAP artifact resolution service or the caller supplies no resolver
// client, and refuses an unknown binding name.
func TestArtifactBindingFailsClosedAtConstruction(t *testing.T) {
	if _, err := NewServiceProvider(artifactConfig(artifactIdPMetadata(t, false))); err == nil || !strings.Contains(err.Error(), "ArtifactResolutionService") {
		t.Fatalf("artifact binding without a resolution service = %v", err)
	}
	cfg := artifactConfig(artifactIdPMetadata(t, true))
	cfg.NewArtifactResolver = nil
	if _, err := NewServiceProvider(cfg); err == nil || !strings.Contains(err.Error(), "resolver client") {
		t.Fatalf("artifact binding without a resolver = %v", err)
	}
	cfg = artifactConfig(artifactIdPMetadata(t, true))
	cfg.ResponseBinding = "redirect"
	if _, err := NewServiceProvider(cfg); err == nil || !strings.Contains(err.Error(), "response_binding") {
		t.Fatalf("unknown binding = %v", err)
	}
	sp, err := NewServiceProvider(artifactConfig(artifactIdPMetadata(t, true)))
	if err != nil || !sp.ArtifactBinding() {
		t.Fatalf("artifact SP = %v %v", sp, err)
	}
}

// A76: an artifact SP asks the IdP for the HTTP-Artifact result binding; a
// POST SP keeps asking for POST, and refuses an artifact it never asked for.
func TestArtifactBindingShapesTheAuthnRequestAndRefusesUnrequestedArtifacts(t *testing.T) {
	metadata := artifactIdPMetadata(t, true)
	artifactSP, err := NewServiceProvider(artifactConfig(metadata))
	if err != nil {
		t.Fatal(err)
	}
	postCfg := artifactConfig(metadata)
	postCfg.ResponseBinding = ""
	postSP, err := NewServiceProvider(postCfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		sp   *ServiceProvider
		want string
	}{{"artifact", artifactSP, saml.HTTPArtifactBinding}, {"post", postSP, saml.HTTPPostBinding}} {
		redirect, err := tc.sp.LoginRedirect("state-1")
		if err != nil {
			t.Fatalf("%s login redirect: %v", tc.name, err)
		}
		if got := authnRequestProtocolBinding(t, redirect.URL); got != tc.want {
			t.Fatalf("%s AuthnRequest ProtocolBinding = %q, want %q", tc.name, got, tc.want)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, "https://app.example.test/auth/saml/acs?SAMLart=AAQAA&RelayState=state-1", nil)
	if _, err := postSP.VerifyResponse(req, []string{"request-1"}); err == nil || !strings.Contains(err.Error(), "artifact binding is not enabled") {
		t.Fatalf("POST SP given an artifact = %v, want a refusal", err)
	}
	empty, _ := http.NewRequest(http.MethodGet, "https://app.example.test/auth/saml/acs", nil)
	if _, err := artifactSP.VerifyResponse(empty, nil); err == nil || !strings.Contains(err.Error(), "neither SAMLResponse nor SAMLart") {
		t.Fatalf("ACS request without a response = %v", err)
	}
}

func authnRequestProtocolBinding(t *testing.T, redirectURL string) string {
	t.Helper()
	u, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("decode SAMLRequest: %v", err)
	}
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("inflate SAMLRequest: %v", err)
	}
	var request struct {
		ProtocolBinding string `xml:",attr"`
	}
	if err := xml.Unmarshal(inflated, &request); err != nil {
		t.Fatalf("decode AuthnRequest: %v (%s)", err, inflated)
	}
	return request.ProtocolBinding
}
