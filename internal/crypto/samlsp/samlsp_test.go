// SPDX-License-Identifier: MPL-2.0

package samlsp

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"

	"trstctl.com/trstctl/internal/crypto/samltest"
)

func TestAUD58RequiredRequestCorrelationDisablesIDPInitiatedAssertions(t *testing.T) {
	sp := aud58SAMLServiceProvider(t, true)
	if sp.sp.AllowIDPInitiated {
		t.Fatal("request-correlated Provider SAML unexpectedly allows IdP-initiated assertions")
	}
	if err := sp.sp.ValidateRequestID(saml.Response{}, []string{"request-1"}); err == nil {
		t.Fatal("empty InResponseTo passed the required request-ID check")
	}
	if err := sp.sp.ValidateRequestID(saml.Response{InResponseTo: "request-1"}, []string{"request-1"}); err != nil {
		t.Fatalf("matching InResponseTo failed: %v", err)
	}
}

func FuzzAUD58SAMLResponseParserNeverPanics(f *testing.F) {
	sp := aud58SAMLServiceProvider(f, true)
	f.Add([]byte(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="bad" InResponseTo="request-1"></Response>`))
	f.Add([]byte(`<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><Response>&x;</Response>`))
	f.Fuzz(func(t *testing.T, rawXML []byte) {
		if len(rawXML) > 128<<10 {
			t.Skip()
		}
		form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(rawXML)}}
		req, err := http.NewRequest(http.MethodPost, "https://provider.example.test/provider/v1/auth/saml/acs", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = sp.VerifyResponse(req, []string{"request-1"})
	})
}

type samlTestingT interface {
	Helper()
	Fatalf(string, ...any)
}

func aud58SAMLServiceProvider(t samlTestingT, requireCorrelation bool) *ServiceProvider {
	t.Helper()
	key, cert, err := samltest.NewIdentityProviderMaterial("aud58-provider-idp")
	if err != nil {
		t.Fatalf("generate IdP material: %v", err)
	}
	metadataURL := mustAUD58URL(t, "https://idp.example.test/metadata")
	ssoURL := mustAUD58URL(t, "https://idp.example.test/sso")
	idp := saml.IdentityProvider{Certificate: cert, Key: key, MetadataURL: metadataURL, SSOURL: ssoURL}
	metadata, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatalf("marshal IdP metadata: %v", err)
	}
	sp, err := NewServiceProvider(Config{
		EntityID:       "https://provider.example.test/provider/v1/auth/saml/metadata",
		MetadataURL:    "https://provider.example.test/provider/v1/auth/saml/metadata",
		ACSURL:         "https://provider.example.test/provider/v1/auth/saml/acs",
		IDPMetadataXML: string(metadata), RequireRequestCorrelation: requireCorrelation,
	})
	if err != nil {
		t.Fatalf("build SAML SP: %v", err)
	}
	return sp
}

func mustAUD58URL(t samlTestingT, raw string) url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return *u
}
