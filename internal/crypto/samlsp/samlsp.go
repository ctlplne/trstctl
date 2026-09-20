// SPDX-License-Identifier: BUSL-1.1

// Package samlsp keeps SAML XML signature verification behind the internal
// cryptography boundary (AN-3). Callers get URLs, metadata bytes, and normalized
// verified assertion fields; they do not touch XMLDSig, x509, or private-key
// primitives directly.
package samlsp

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	crewjamsamlsp "github.com/crewjam/saml/samlsp"
)

// Config is the SP material needed to verify SAML responses offline.
type Config struct {
	EntityID       string
	MetadataURL    string
	ACSURL         string
	IDPMetadataXML string
	// RequireRequestCorrelation refuses IdP-initiated assertions and requires
	// both the Response and SubjectConfirmation InResponseTo values to match one
	// of the caller-supplied request IDs. Provider workforce login enables this
	// because the browser always starts at its SP login route.
	RequireRequestCorrelation bool
}

// Redirect is an SP-initiated login redirect plus the generated request ID.
type Redirect struct {
	URL       string
	RequestID string
}

// Assertion is the verified, normalized subset of a SAML assertion that callers
// may use for session issuance and tenant mapping.
type Assertion struct {
	Subject    string
	Issuer     string
	Attributes map[string][]string
}

// ServiceProvider verifies SAML responses for one configured IdP.
type ServiceProvider struct {
	sp *saml.ServiceProvider
}

// NewServiceProvider builds a SAML SP from operator configuration.
func NewServiceProvider(cfg Config) (*ServiceProvider, error) {
	if cfg.EntityID == "" {
		return nil, errors.New("samlsp: entity_id is required")
	}
	metadataURL, err := parseAbsoluteURL(cfg.MetadataURL, "metadata_url")
	if err != nil {
		return nil, err
	}
	acsURL, err := parseAbsoluteURL(cfg.ACSURL, "acs_url")
	if err != nil {
		return nil, err
	}
	if cfg.IDPMetadataXML == "" {
		return nil, errors.New("samlsp: idp_metadata_xml is required")
	}
	idpMetadata, err := crewjamsamlsp.ParseMetadata([]byte(cfg.IDPMetadataXML))
	if err != nil {
		return nil, fmt.Errorf("samlsp: parse IdP metadata: %w", err)
	}
	sp := &saml.ServiceProvider{
		EntityID:              cfg.EntityID,
		MetadataURL:           metadataURL,
		AcsURL:                acsURL,
		IDPMetadata:           idpMetadata,
		AllowIDPInitiated:     !cfg.RequireRequestCorrelation,
		AuthnNameIDFormat:     saml.EmailAddressNameIDFormat,
		ValidateRequestID:     validateRequestIDWhenPresent,
		DefaultRedirectURI:    "/",
		MetadataValidDuration: saml.DefaultValidDuration,
	}
	if cfg.RequireRequestCorrelation {
		sp.ValidateRequestID = validateRequiredRequestID
	}
	return &ServiceProvider{sp: sp}, nil
}

// LoginRedirect creates an HTTP-Redirect binding AuthnRequest to the IdP.
func (p *ServiceProvider) LoginRedirect(relayState string) (Redirect, error) {
	req, err := p.sp.MakeAuthenticationRequest(p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return Redirect{}, err
	}
	u, err := req.Redirect(relayState, p.sp)
	if err != nil {
		return Redirect{}, err
	}
	return Redirect{URL: u.String(), RequestID: req.ID}, nil
}

// MetadataXML returns this SP's SAML metadata document.
func (p *ServiceProvider) MetadataXML() ([]byte, error) {
	return xml.MarshalIndent(p.sp.Metadata(), "", "  ")
}

// VerifyResponse parses, signature-verifies, and validates a POST-binding SAML
// response from the ACS request.
func (p *ServiceProvider) VerifyResponse(r *http.Request, possibleRequestIDs []string) (Assertion, error) {
	if err := r.ParseForm(); err != nil {
		return Assertion{}, err
	}
	assertion, err := p.sp.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		var invalid *saml.InvalidResponseError
		if errors.As(err, &invalid) && invalid.PrivateErr != nil {
			return Assertion{}, fmt.Errorf("samlsp: verify response: %w: %v", err, invalid.PrivateErr)
		}
		return Assertion{}, err
	}
	return normalizeAssertion(assertion), nil
}

func parseAbsoluteURL(raw, name string) (url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return url.URL{}, fmt.Errorf("samlsp: %s %q must be an absolute URL", name, raw)
	}
	return *u, nil
}

func validateRequestIDWhenPresent(response saml.Response, possibleRequestIDs []string) error {
	if len(possibleRequestIDs) == 0 {
		return nil
	}
	for _, id := range possibleRequestIDs {
		if id != "" && response.InResponseTo == id {
			return nil
		}
	}
	return fmt.Errorf("samlsp: InResponseTo %q does not match %v", response.InResponseTo, possibleRequestIDs)
}

func validateRequiredRequestID(response saml.Response, possibleRequestIDs []string) error {
	if len(possibleRequestIDs) == 0 || response.InResponseTo == "" {
		return errors.New("samlsp: request correlation is required")
	}
	for _, id := range possibleRequestIDs {
		if id != "" && response.InResponseTo == id {
			return nil
		}
	}
	return fmt.Errorf("samlsp: InResponseTo %q does not match %v", response.InResponseTo, possibleRequestIDs)
}

func normalizeAssertion(a *saml.Assertion) Assertion {
	out := Assertion{Issuer: a.Issuer.Value, Attributes: map[string][]string{}}
	if a.Subject != nil && a.Subject.NameID != nil {
		out.Subject = a.Subject.NameID.Value
	}
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			values := make([]string, 0, len(attr.Values))
			for _, v := range attr.Values {
				if v.Value != "" {
					values = append(values, v.Value)
				} else if v.NameID != nil && v.NameID.Value != "" {
					values = append(values, v.NameID.Value)
				}
			}
			if len(values) == 0 {
				continue
			}
			addAttr(out.Attributes, attr.Name, values)
			addAttr(out.Attributes, attr.FriendlyName, values)
		}
	}
	return out
}

func addAttr(attrs map[string][]string, name string, values []string) {
	if name == "" {
		return
	}
	attrs[name] = append(attrs[name], values...)
}
