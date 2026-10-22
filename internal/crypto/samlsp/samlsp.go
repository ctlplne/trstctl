// SPDX-License-Identifier: BUSL-1.1

// Package samlsp keeps SAML XML signature verification behind the internal
// cryptography boundary (AN-3). Callers get URLs, metadata bytes, and normalized
// verified assertion fields; they do not touch XMLDSig, x509, or private-key
// primitives directly.
package samlsp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

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
	// ResponseBinding is how the IdP returns the assertion: ResponseBindingPost
	// (the default) or ResponseBindingArtifact, where the browser carries only
	// an opaque artifact to the ACS and the SP resolves it over a back-channel
	// SOAP call to the IdP's artifact resolution service (A76).
	ResponseBinding string
	// NewArtifactResolver builds the HTTP client used for that back-channel
	// call, given the IdP's artifact resolution endpoint, so the caller's
	// outbound network policy applies to it. Required with the artifact binding.
	NewArtifactResolver func(endpoint string) (*http.Client, error)
	// EncryptionCertDER and EncryptionKeyPKCS8 are the SP's assertion
	// encryption identity (A77): the certificate is advertised in the SP
	// metadata with use="encryption" and the RSA key decrypts
	// EncryptedAssertion elements. The key bytes are copied and the caller's
	// slice may be wiped after construction. Both empty means plaintext only.
	EncryptionCertDER  []byte
	EncryptionKeyPKCS8 []byte
}

// Response bindings an SP may ask the IdP for.
const (
	ResponseBindingPost     = "post"
	ResponseBindingArtifact = "artifact"
)

// ValidResponseBinding reports whether value names a supported response
// binding; empty means the default (POST).
func ValidResponseBinding(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ResponseBindingPost, ResponseBindingArtifact:
		return true
	}
	return false
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
	sp       *saml.ServiceProvider
	artifact bool
	decrypts bool
}

// ArtifactBinding reports whether this SP asks the IdP for the artifact
// response binding.
func (p *ServiceProvider) ArtifactBinding() bool { return p.artifact }

// DecryptsAssertions reports whether this SP advertises an encryption key and
// can decrypt EncryptedAssertion elements (A77).
func (p *ServiceProvider) DecryptsAssertions() bool { return p.decrypts }

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
	if !ValidResponseBinding(cfg.ResponseBinding) {
		return nil, fmt.Errorf("samlsp: response_binding %q must be %q or %q", cfg.ResponseBinding, ResponseBindingPost, ResponseBindingArtifact)
	}
	out := &ServiceProvider{sp: sp}
	if len(cfg.EncryptionCertDER) != 0 || len(cfg.EncryptionKeyPKCS8) != 0 {
		if len(cfg.EncryptionCertDER) == 0 || len(cfg.EncryptionKeyPKCS8) == 0 {
			return nil, errors.New("samlsp: assertion encryption needs both the certificate and the key")
		}
		cert, err := x509.ParseCertificate(cfg.EncryptionCertDER)
		if err != nil {
			return nil, fmt.Errorf("samlsp: parse encryption certificate: %w", err)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(cfg.EncryptionKeyPKCS8)
		if err != nil {
			return nil, fmt.Errorf("samlsp: parse encryption key: %w", err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("samlsp: assertion encryption needs an RSA key, not %T (XML Encryption key transport is RSA-OAEP/RSA-1.5)", parsed)
		}
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(key.Public()) {
			return nil, errors.New("samlsp: encryption certificate does not match its key")
		}
		sp.Certificate = cert
		sp.Key = key
		out.decrypts = true
	}
	if strings.EqualFold(strings.TrimSpace(cfg.ResponseBinding), ResponseBindingArtifact) {
		endpoint := sp.GetArtifactBindingLocation(saml.SOAPBinding)
		if endpoint == "" {
			return nil, errors.New("samlsp: response_binding artifact needs an ArtifactResolutionService with the SOAP binding in the IdP metadata; none is declared")
		}
		if cfg.NewArtifactResolver == nil {
			return nil, errors.New("samlsp: response_binding artifact needs an artifact resolver client")
		}
		client, err := cfg.NewArtifactResolver(endpoint)
		if err != nil {
			return nil, fmt.Errorf("samlsp: artifact resolution endpoint %q: %w", endpoint, err)
		}
		sp.HTTPClient = client
		out.artifact = true
	}
	return out, nil
}

// LoginRedirect creates an HTTP-Redirect binding AuthnRequest to the IdP.
func (p *ServiceProvider) LoginRedirect(relayState string) (Redirect, error) {
	resultBinding := saml.HTTPPostBinding
	if p.artifact {
		resultBinding = saml.HTTPArtifactBinding
	}
	req, err := p.sp.MakeAuthenticationRequest(p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, resultBinding)
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

// VerifyResponse parses, signature-verifies, and validates the SAML response
// from the ACS request: a POST-binding SAMLResponse, or, when this SP uses the
// artifact binding, a SAMLart that it resolves over the back-channel first. An
// artifact arriving at an SP that did not ask for the binding is refused.
func (p *ServiceProvider) VerifyResponse(r *http.Request, possibleRequestIDs []string) (Assertion, error) {
	if err := r.ParseForm(); err != nil {
		return Assertion{}, err
	}
	if r.Form.Get("SAMLart") != "" && !p.artifact {
		return Assertion{}, errors.New("samlsp: artifact binding is not enabled for this service provider")
	}
	if r.Form.Get("SAMLart") == "" && r.Form.Get("SAMLResponse") == "" {
		return Assertion{}, errors.New("samlsp: the ACS request carries neither SAMLResponse nor SAMLart")
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
