// Package saml validates signed SAML 2.0 assertions inside the AN-3 crypto
// boundary (a subpackage of internal/crypto). XML-DSig signature verification —
// canonicalization, digesting, and the RSA signature check — is delegated to the
// vetted github.com/russellhaering/goxmldsig library rather than hand-rolled;
// this package adds SAML-level checks (audience, validity window) and extracts
// the subject and attributes. Callers outside the boundary consume only the
// crypto-free Assertion result.
package saml

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Assertion is the validated, extracted content of a SAML assertion.
type Assertion struct {
	Subject      string
	Audience     string
	Attributes   map[string][]string
	NotBefore    time.Time
	NotOnOrAfter time.Time
}

// Validator validates SAML assertions signed by a configured IdP certificate and
// addressed to this service provider.
type Validator struct {
	spEntityID string
	store      dsig.X509CertificateStore
	now        func() time.Time
}

// NewValidator builds a validator for the given SP entity ID, trusting the
// PEM-encoded IdP signing certificate.
func NewValidator(spEntityID string, idpCertPEM []byte) (*Validator, error) {
	block, _ := pem.Decode(idpCertPEM)
	if block == nil {
		return nil, errors.New("saml: idp certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("saml: parse idp certificate: %w", err)
	}
	return &Validator{
		spEntityID: spEntityID,
		store:      &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}},
		now:        time.Now,
	}, nil
}

// Validate verifies the assertion's XML signature against the trusted IdP
// certificate, then checks the audience and validity window, returning the
// subject and attributes. Any failure (bad signature, wrong audience, outside
// the validity window) is a rejection.
func (v *Validator) Validate(assertionXML []byte) (Assertion, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(assertionXML); err != nil {
		return Assertion{}, fmt.Errorf("saml: parse assertion: %w", err)
	}
	el := doc.FindElement("//Assertion")
	if el == nil {
		return Assertion{}, errors.New("saml: no Assertion element")
	}

	ctx := dsig.NewDefaultValidationContext(v.store)
	ctx.IdAttribute = "ID"
	validated, err := ctx.Validate(el)
	if err != nil {
		return Assertion{}, fmt.Errorf("saml: signature validation failed: %w", err)
	}

	a, err := extract(validated)
	if err != nil {
		return Assertion{}, err
	}
	if a.Audience != v.spEntityID {
		return Assertion{}, fmt.Errorf("saml: assertion audience %q is not this service provider %q", a.Audience, v.spEntityID)
	}
	now := v.now()
	if now.Before(a.NotBefore) || !now.Before(a.NotOnOrAfter) {
		return Assertion{}, fmt.Errorf("saml: assertion is outside its validity window [%s, %s)", a.NotBefore, a.NotOnOrAfter)
	}
	return a, nil
}

func extract(el *etree.Element) (Assertion, error) {
	a := Assertion{Attributes: map[string][]string{}}

	if nameID := el.FindElement("./Subject/NameID"); nameID != nil {
		a.Subject = nameID.Text()
	}
	if a.Subject == "" {
		return Assertion{}, errors.New("saml: assertion has no Subject NameID")
	}

	cond := el.FindElement("./Conditions")
	if cond == nil {
		return Assertion{}, errors.New("saml: assertion has no Conditions")
	}
	if aud := cond.FindElement("./AudienceRestriction/Audience"); aud != nil {
		a.Audience = aud.Text()
	}
	var err error
	if a.NotBefore, err = parseTime(cond.SelectAttrValue("NotBefore", "")); err != nil {
		return Assertion{}, fmt.Errorf("saml: NotBefore: %w", err)
	}
	if a.NotOnOrAfter, err = parseTime(cond.SelectAttrValue("NotOnOrAfter", "")); err != nil {
		return Assertion{}, fmt.Errorf("saml: NotOnOrAfter: %w", err)
	}

	for _, attr := range el.FindElements("./AttributeStatement/Attribute") {
		name := attr.SelectAttrValue("Name", "")
		if name == "" {
			continue
		}
		for _, val := range attr.FindElements("./AttributeValue") {
			a.Attributes[name] = append(a.Attributes[name], val.Text())
		}
	}
	return a, nil
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("missing timestamp")
	}
	return time.Parse(time.RFC3339, s)
}
