// SPDX-License-Identifier: BUSL-1.1

package samlsp

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"

	"trstctl.com/trstctl/internal/crypto/samltest"
)

type sloIdP struct {
	key      any
	cert     *x509.Certificate
	entityID string
	metadata string
}

func newSLOIdP(t *testing.T, withSLO bool) sloIdP {
	t.Helper()
	key, cert, err := samltest.NewIdentityProviderMaterial("a78-idp")
	if err != nil {
		t.Fatal(err)
	}
	idp := saml.IdentityProvider{Certificate: cert, Key: key,
		MetadataURL: mustAUD58URL(t, "https://idp.example.test/metadata"), SSOURL: mustAUD58URL(t, "https://idp.example.test/sso")}
	if withSLO {
		idp.LogoutURL = mustAUD58URL(t, "https://idp.example.test/slo")
	}
	metadata, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	return sloIdP{key: key, cert: cert, entityID: idp.Metadata().EntityID, metadata: string(metadata)}
}

func sloConfig(metadata string) Config {
	cfg := artifactConfig(metadata)
	cfg.ResponseBinding = ""
	cfg.SingleLogout = true
	cfg.SLOURL = "https://app.example.test/auth/saml/slo"
	return cfg
}

func inflateQuery(t *testing.T, rawURL, param string) []byte {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(u.Query().Get(param))
	if err != nil {
		t.Fatalf("decode %s: %v", param, err)
	}
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("inflate %s: %v", param, err)
	}
	return inflated
}

// A78: single logout fails closed without an IdP SingleLogoutService; the SP's
// LogoutRequest names the IdP session (NameID and SessionIndex) and returns
// the request ID the IdP's answer must carry.
func TestSingleLogoutConstructionAndLogoutRequest(t *testing.T) {
	if _, err := NewServiceProvider(sloConfig(newSLOIdP(t, false).metadata)); err == nil || !strings.Contains(err.Error(), "SingleLogoutService") {
		t.Fatalf("single logout without an IdP SLO service = %v", err)
	}
	idp := newSLOIdP(t, true)
	sp, err := NewServiceProvider(sloConfig(idp.metadata))
	if err != nil || !sp.SingleLogout() {
		t.Fatalf("SLO SP = %v %v", sp, err)
	}
	redirect, err := sp.LogoutRedirect("alice@example.test", "session-7", "state-1")
	if err != nil || redirect.RequestID == "" || !strings.HasPrefix(redirect.URL, "https://idp.example.test/slo?") {
		t.Fatalf("logout redirect = %+v %v", redirect, err)
	}
	var req saml.LogoutRequest
	if err := xml.Unmarshal(inflateQuery(t, redirect.URL, "SAMLRequest"), &req); err != nil {
		t.Fatal(err)
	}
	if req.ID != redirect.RequestID || req.NameID == nil || req.NameID.Value != "alice@example.test" || req.SessionIndex == nil || req.SessionIndex.Value != "session-7" || req.Destination != "https://idp.example.test/slo" {
		t.Fatalf("logout request = %+v", req)
	}
	if _, err := sp.LogoutRedirect("", "", "state"); err == nil {
		t.Fatal("a logout request without a NameID was built")
	}
}

func signedLogoutRequest(t *testing.T, idp sloIdP, destination, issuer, nameID string, issued time.Time) []byte {
	t.Helper()
	req := saml.LogoutRequest{
		ID: "id-idp-logout-1", Version: "2.0", IssueInstant: issued, Destination: destination,
		Issuer:       &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: issuer},
		NameID:       &saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: nameID},
		SessionIndex: &saml.SessionIndex{Value: "session-7"},
	}
	raw, err := req.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := samltest.SignEnvelopedXML(idp.key, idp.cert, raw)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func postLogout(t *testing.T, param string, body []byte) *http.Request {
	t.Helper()
	form := url.Values{param: {base64.StdEncoding.EncodeToString(body)}, "RelayState": {"rs"}}
	r, _ := http.NewRequest(http.MethodPost, "https://app.example.test/auth/saml/slo", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// A78: an IdP-initiated LogoutRequest is accepted only when signed by the
// IdP's metadata certificate, addressed to this SP's SLO URL, issued by the
// IdP, fresh and naming a NameID; the SP answers it with a Success
// LogoutResponse bound to the request ID.
func TestIdPInitiatedLogoutRequestIsVerifiedAndAnswered(t *testing.T) {
	idp := newSLOIdP(t, true)
	sp, err := NewServiceProvider(sloConfig(idp.metadata))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	good := signedLogoutRequest(t, idp, "https://app.example.test/auth/saml/slo", idp.entityID, "alice@example.test", now)
	logout, err := sp.VerifyLogoutRequest(postLogout(t, "SAMLRequest", good))
	if err != nil || logout.NameID != "alice@example.test" || logout.SessionIndex != "session-7" || logout.ID != "id-idp-logout-1" || logout.Issuer != idp.entityID {
		t.Fatalf("verified logout request = %+v %v", logout, err)
	}
	for name, body := range map[string][]byte{
		"unsigned":          mustBytes(t, &saml.LogoutRequest{ID: "x", Version: "2.0", IssueInstant: now, Destination: "https://app.example.test/auth/saml/slo", Issuer: &saml.Issuer{Value: idp.entityID}, NameID: &saml.NameID{Value: "alice@example.test"}}),
		"wrong destination": signedLogoutRequest(t, idp, "https://other.example.test/slo", idp.entityID, "alice@example.test", now),
		"wrong issuer":      signedLogoutRequest(t, idp, "https://app.example.test/auth/saml/slo", "https://rogue.example.test", "alice@example.test", now),
		"stale":             signedLogoutRequest(t, idp, "https://app.example.test/auth/saml/slo", idp.entityID, "alice@example.test", now.Add(-10*time.Minute)),
		"other signer":      signedBy(t, newSLOIdP(t, true), "https://app.example.test/auth/saml/slo", idp.entityID, "alice@example.test", now),
	} {
		if _, err := sp.VerifyLogoutRequest(postLogout(t, "SAMLRequest", body)); err == nil {
			t.Fatalf("%s logout request was accepted", name)
		}
	}
	responseURL, err := sp.LogoutResponseRedirect(logout.ID, "rs")
	if err != nil || !strings.HasPrefix(responseURL, "https://idp.example.test/slo?") {
		t.Fatalf("logout response redirect = %q %v", responseURL, err)
	}
	var resp saml.LogoutResponse
	if err := xml.Unmarshal(inflateQuery(t, responseURL, "SAMLResponse"), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.InResponseTo != logout.ID || resp.Status.StatusCode.Value != saml.StatusSuccess {
		t.Fatalf("logout response = %+v", resp)
	}
}

func signedBy(t *testing.T, signer sloIdP, destination, issuer, nameID string, issued time.Time) []byte {
	t.Helper()
	return signedLogoutRequest(t, signer, destination, issuer, nameID, issued)
}

func mustBytes(t *testing.T, req *saml.LogoutRequest) []byte {
	t.Helper()
	raw, err := req.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A78: the IdP's LogoutResponse must answer the request this browser started.
func TestLogoutResponseMustAnswerTheBrowsersRequest(t *testing.T) {
	idp := newSLOIdP(t, true)
	sp, err := NewServiceProvider(sloConfig(idp.metadata))
	if err != nil {
		t.Fatal(err)
	}
	build := func(inResponseTo string) []byte {
		resp := saml.LogoutResponse{ID: "id-resp-1", InResponseTo: inResponseTo, Version: "2.0", IssueInstant: time.Now().UTC(),
			Destination: "https://app.example.test/auth/saml/slo", Issuer: &saml.Issuer{Value: idp.entityID},
			Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}}
		doc := etree.NewDocument()
		doc.SetRoot(resp.Element())
		raw, err := doc.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		signed, err := samltest.SignEnvelopedXML(idp.key, idp.cert, raw)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	if err := sp.VerifyLogoutResponse(postLogout(t, "SAMLResponse", build("id-req-1")), "id-req-1"); err != nil {
		t.Fatalf("matching logout response refused: %v", err)
	}
	if err := sp.VerifyLogoutResponse(postLogout(t, "SAMLResponse", build("id-req-2")), "id-req-1"); err == nil {
		t.Fatal("a logout response for another request was accepted")
	}
}
