// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/crypto/samlsp"
)

// SAMLVerifier turns a cryptographically verified SAML assertion into the same
// Claims shape the OIDC verifier returns, so tenant mapping and session issuance
// stay one path.
type SAMLVerifier struct {
	Provider *samlsp.ServiceProvider

	SubjectAttribute string
	EmailAttribute   string
	TenantClaim      string
	GroupsClaim      string
}

// LoginRedirect starts an SP-initiated login and returns the IdP redirect plus
// the generated SAML request ID.
func (v SAMLVerifier) LoginRedirect(relayState string) (samlsp.Redirect, error) {
	if v.Provider == nil {
		return samlsp.Redirect{}, errors.New("auth: SAML provider is not configured")
	}
	return v.Provider.LoginRedirect(relayState)
}

// MetadataXML returns this service provider's metadata document.
func (v SAMLVerifier) MetadataXML() ([]byte, error) {
	if v.Provider == nil {
		return nil, errors.New("auth: SAML provider is not configured")
	}
	return v.Provider.MetadataXML()
}

// Verify validates the ACS request's SAMLResponse and extracts login claims.
func (v SAMLVerifier) Verify(r *http.Request, possibleRequestIDs []string) (Claims, error) {
	if v.Provider == nil {
		return Claims{}, errors.New("auth: SAML provider is not configured")
	}
	assertion, err := v.Provider.VerifyResponse(r, possibleRequestIDs)
	if err != nil {
		return Claims{}, err
	}
	subject := assertion.Subject
	if v.SubjectAttribute != "" {
		subject = firstAttribute(assertion.Attributes, v.SubjectAttribute)
	}
	if subject == "" {
		return Claims{}, errors.New("auth: SAML assertion has no subject")
	}
	email := firstAttribute(assertion.Attributes, v.EmailAttribute, "email", "mail", "urn:oid:0.9.2342.19200300.100.1.3")
	return Claims{
		Subject: subject,
		Email:   email,
		Issuer:  assertion.Issuer,
		Tenant:  firstAttribute(assertion.Attributes, v.TenantClaim),
		Groups:  attributeValues(assertion.Attributes, v.GroupsClaim),
	}, nil
}

func firstAttribute(attrs map[string][]string, names ...string) string {
	for _, name := range names {
		if name == "" {
			continue
		}
		values := attrs[name]
		if len(values) > 0 && values[0] != "" {
			return values[0]
		}
	}
	return ""
}

func attributeValues(attrs map[string][]string, name string) []string {
	if name == "" {
		return nil
	}
	values := attrs[name]
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}
