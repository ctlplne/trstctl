// SPDX-License-Identifier: BUSL-1.1

package samlsp

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/samltest"
)

const (
	cr651ACS      = "https://app.example.test/auth/saml/acs"
	cr651Entity   = "https://app.example.test/auth/saml/metadata"
	cr651SLO      = "https://app.example.test/auth/saml/slo"
	cr651SAMLNS   = `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`
	cr651SAMLPNS  = `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`
	cr651EmailFmt = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
)

func cr651Time(now time.Time) string { return now.UTC().Format(time.RFC3339) }

func cr651SP(t *testing.T) (*ServiceProvider, sloIdP) {
	t.Helper()
	idp := newSLOIdP(t, false)
	cfg := artifactConfig(idp.metadata)
	cfg.ResponseBinding = ""
	sp, err := NewServiceProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return sp, idp
}

func cr651Assertion(idpEntity, subject, conditions string, now time.Time) string {
	return `<saml:Assertion ID="id-cr651-assertion" Version="2.0" IssueInstant="` + cr651Time(now) + `">` +
		`<saml:Issuer>` + idpEntity + `</saml:Issuer>` + subject + conditions +
		`<saml:AuthnStatement AuthnInstant="` + cr651Time(now) + `" SessionIndex="idp-cr651">` +
		`<saml:AuthnContext><saml:AuthnContextClassRef>` +
		`urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` +
		`</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>`
}

func cr651Subject(now time.Time, nameID string) string {
	return `<saml:Subject>` + nameID +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<saml:SubjectConfirmationData NotOnOrAfter="` + cr651Time(now.Add(5*time.Minute)) +
		`" Recipient="` + cr651ACS + `"/></saml:SubjectConfirmation></saml:Subject>`
}

func cr651Conditions(now time.Time) string {
	return `<saml:Conditions NotBefore="` + cr651Time(now.Add(-time.Minute)) +
		`" NotOnOrAfter="` + cr651Time(now.Add(5*time.Minute)) + `">` +
		`<saml:AudienceRestriction><saml:Audience>` + cr651Entity +
		`</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
}

func cr651SignedACSRequest(t *testing.T, idp sloIdP, assertion string, now time.Time) *http.Request {
	t.Helper()
	response := `<samlp:Response ` + cr651SAMLPNS + ` ` + cr651SAMLNS +
		` ID="id-cr651-response" Version="2.0" IssueInstant="` + cr651Time(now) +
		`" Destination="` + cr651ACS + `"><saml:Issuer>` + idp.entityID + `</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>` +
		`</samlp:Status>` + assertion + `</samlp:Response>`
	signed, err := samltest.SignEnvelopedXML(idp.key, idp.cert, []byte(response))
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(signed)}}
	r, err := http.NewRequest(http.MethodPost, cr651ACS, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func cr651Verify(sp *ServiceProvider, r *http.Request) (a Assertion, panicked any, err error) {
	defer func() { panicked = recover() }()
	a, err = sp.VerifyResponse(r, nil)
	return a, nil, err
}

func TestCR651SignedAssertionMissingIssuerIsRejectedWithoutPanic(t *testing.T) {
	sp, idp := cr651SP(t)
	now := time.Now()
	nameID := `<saml:NameID Format="` + cr651EmailFmt + `">alice@example.test</saml:NameID>`
	good := cr651Assertion(idp.entityID, cr651Subject(now, nameID), cr651Conditions(now), now)
	if a, panicValue, err := cr651Verify(sp, cr651SignedACSRequest(t, idp, good, now)); panicValue != nil || err != nil || a.Subject != "alice@example.test" {
		t.Fatalf("valid signed control = %+v, err %v, panic %v", a, err, panicValue)
	}
	missingIssuer := strings.Replace(good, `<saml:Issuer>`+idp.entityID+`</saml:Issuer>`, "", 1)
	a, panicValue, err := cr651Verify(sp, cr651SignedACSRequest(t, idp, missingIssuer, now))
	if panicValue != nil || err == nil {
		t.Fatalf("signed assertion without issuer = %+v, err %v, panic %v; want a refusal without panic", a, err, panicValue)
	}
}

func TestCR651SignedAssertionMissingValidationFieldsIsRejectedWithoutPanic(t *testing.T) {
	sp, idp := cr651SP(t)
	now := time.Now()
	nameID := `<saml:NameID Format="` + cr651EmailFmt + `">alice@example.test</saml:NameID>`
	subject := cr651Subject(now, nameID)
	for name, assertion := range map[string]string{
		"no Subject":    cr651Assertion(idp.entityID, "", cr651Conditions(now), now),
		"no Conditions": cr651Assertion(idp.entityID, subject, "", now),
		"no SubjectConfirmationData": cr651Assertion(idp.entityID,
			strings.Replace(subject, `<saml:SubjectConfirmationData NotOnOrAfter="`+cr651Time(now.Add(5*time.Minute))+`" Recipient="`+cr651ACS+`"/>`, "", 1),
			cr651Conditions(now), now),
	} {
		t.Run(name, func(t *testing.T) {
			a, panicValue, err := cr651Verify(sp, cr651SignedACSRequest(t, idp, assertion, now))
			if panicValue != nil || err == nil {
				t.Fatalf("signed assertion missing %s = %+v, err %v, panic %v; want a refusal without panic", name, a, err, panicValue)
			}
		})
	}
}

func TestCR651ForeignNamespaceNameIDCannotSpoofSubject(t *testing.T) {
	sp, idp := cr651SP(t)
	now := time.Now()
	foreign := `<x:NameID xmlns:x="urn:example:not-saml" Format="` + cr651EmailFmt + `">bob@example.test</x:NameID>`
	real := `<saml:NameID Format="` + cr651EmailFmt + `">alice@example.test</saml:NameID>`
	for name, nameID := range map[string]string{
		"foreign only":       foreign,
		"foreign after real": real + foreign,
	} {
		t.Run(name, func(t *testing.T) {
			assertion := cr651Assertion(idp.entityID, cr651Subject(now, nameID), cr651Conditions(now), now)
			a, panicValue, err := cr651Verify(sp, cr651SignedACSRequest(t, idp, assertion, now))
			if panicValue != nil {
				t.Fatalf("signed assertion panicked: %v", panicValue)
			}
			if err == nil && a.Subject == "bob@example.test" {
				t.Fatalf("foreign namespace NameID impersonated a subject: %+v", a)
			}
		})
	}
}

func TestCR651SignedLogoutResponseMissingIssuerIsRejectedWithoutPanic(t *testing.T) {
	idp := newSLOIdP(t, true)
	sp, err := NewServiceProvider(sloConfig(idp.metadata))
	if err != nil {
		t.Fatal(err)
	}
	response := `<samlp:LogoutResponse ` + cr651SAMLPNS + ` ` + cr651SAMLNS +
		` ID="id-cr651-logout" InResponseTo="id-cr651-request" Version="2.0" IssueInstant="` +
		cr651Time(time.Now()) + `" Destination="` + cr651SLO + `">` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>` +
		`</samlp:Status></samlp:LogoutResponse>`
	signed, err := samltest.SignEnvelopedXML(idp.key, idp.cert, []byte(response))
	if err != nil {
		t.Fatal(err)
	}
	var panicValue any
	func() {
		defer func() { panicValue = recover() }()
		err = sp.VerifyLogoutResponse(postLogout(t, "SAMLResponse", signed), "id-cr651-request")
	}()
	if panicValue != nil || err == nil {
		t.Fatalf("signed logout response without issuer = err %v, panic %v; want a refusal without panic", err, panicValue)
	}
}
