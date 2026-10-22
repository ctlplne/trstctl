// SPDX-License-Identifier: BUSL-1.1

package samlsp

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"trstctl.com/trstctl/internal/crypto"
)

// maxLogoutMessageBytes bounds a decoded LogoutRequest/LogoutResponse.
const maxLogoutMessageBytes = 256 << 10

// LogoutRedirect builds the SP-initiated LogoutRequest for the IdP's redirect
// SLO endpoint (A78), naming the IdP session by NameID and, when known, its
// SessionIndex; signed when this SP holds a key. The request ID returned is
// what the IdP's LogoutResponse must answer.
func (p *ServiceProvider) LogoutRedirect(nameID, sessionIndex, relayState string) (Redirect, error) {
	if !p.slo {
		return Redirect{}, errors.New("samlsp: single logout is not enabled for this service provider")
	}
	if strings.TrimSpace(nameID) == "" {
		return Redirect{}, errors.New("samlsp: a logout request needs the IdP NameID")
	}
	req := saml.LogoutRequest{
		ID: fmt.Sprintf("id-%x", randomID()), IssueInstant: saml.TimeNow(), Version: "2.0",
		Destination: p.sp.GetSLOBindingLocation(saml.HTTPRedirectBinding),
		Issuer:      &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: p.sp.EntityID},
		NameID: &saml.NameID{Format: string(p.sp.AuthnNameIDFormat), Value: nameID,
			NameQualifier: p.sp.IDPMetadata.EntityID, SPNameQualifier: p.sp.EntityID},
	}
	if sessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: sessionIndex}
	}
	if p.sp.SignatureMethod != "" {
		if err := p.sp.SignLogoutRequest(&req); err != nil {
			return Redirect{}, fmt.Errorf("samlsp: sign logout request: %w", err)
		}
	}
	return Redirect{URL: req.Redirect(relayState).String(), RequestID: req.ID}, nil
}

// VerifyLogoutResponse validates the IdP's LogoutResponse to the SP's own
// LogoutRequest (signature against the IdP metadata, destination, issuer,
// freshness and Success status through the library) and additionally requires
// it to answer the given request ID, which the library does not check.
func (p *ServiceProvider) VerifyLogoutResponse(r *http.Request, requestID string) error {
	if !p.slo {
		return errors.New("samlsp: single logout is not enabled for this service provider")
	}
	if err := p.sp.ValidateLogoutResponseRequest(r); err != nil {
		var invalid *saml.InvalidResponseError
		if errors.As(err, &invalid) && invalid.PrivateErr != nil {
			return fmt.Errorf("samlsp: verify logout response: %w: %v", err, invalid.PrivateErr)
		}
		return fmt.Errorf("samlsp: verify logout response: %w", err)
	}
	raw, err := decodeLogoutMessage(r, "SAMLResponse")
	if err != nil {
		return err
	}
	var resp saml.LogoutResponse
	if err := xml.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("samlsp: decode logout response: %w", err)
	}
	if requestID == "" || resp.InResponseTo != requestID {
		return fmt.Errorf("samlsp: logout response answers %q, not this sign-out's request", resp.InResponseTo)
	}
	return nil
}

// VerifyLogoutRequest validates an IdP-initiated LogoutRequest delivered by
// the redirect or POST binding: well-formed XML, an enveloped signature by an
// IdP signing certificate from the metadata, this SP's SLO URL as the
// destination, the IdP's entity ID as the issuer, a fresh IssueInstant, an
// unexpired NotOnOrAfter and a NameID.
func (p *ServiceProvider) VerifyLogoutRequest(r *http.Request) (LogoutRequest, error) {
	if !p.slo {
		return LogoutRequest{}, errors.New("samlsp: single logout is not enabled for this service provider")
	}
	raw, err := decodeLogoutMessage(r, "SAMLRequest")
	if err != nil {
		return LogoutRequest{}, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return LogoutRequest{}, errors.New("samlsp: logout request is not well-formed XML")
	}
	root := doc.Root()
	if root.Tag != "LogoutRequest" || root.NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:protocol" {
		return LogoutRequest{}, errors.New("samlsp: expected a samlp:LogoutRequest")
	}
	certs, err := idpSigningCertificates(p.sp.IDPMetadata)
	if err != nil {
		return LogoutRequest{}, err
	}
	validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	validated, err := validation.Validate(root)
	if err != nil {
		return LogoutRequest{}, fmt.Errorf("samlsp: logout request signature: %w", err)
	}
	validatedDoc := etree.NewDocument()
	validatedDoc.SetRoot(validated)
	validatedXML, err := validatedDoc.WriteToBytes()
	if err != nil {
		return LogoutRequest{}, err
	}
	var req saml.LogoutRequest
	if err := xml.Unmarshal(validatedXML, &req); err != nil {
		return LogoutRequest{}, fmt.Errorf("samlsp: decode logout request: %w", err)
	}
	now := saml.TimeNow()
	switch {
	case req.Destination != p.sp.SloURL.String():
		return LogoutRequest{}, fmt.Errorf("samlsp: logout request destination %q is not this SP's SLO URL", req.Destination)
	case req.Issuer == nil || req.Issuer.Value != p.sp.IDPMetadata.EntityID:
		return LogoutRequest{}, errors.New("samlsp: logout request issuer is not the configured IdP")
	case req.IssueInstant.Add(saml.MaxIssueDelay).Before(now):
		return LogoutRequest{}, errors.New("samlsp: logout request IssueInstant is too old")
	case req.NotOnOrAfter != nil && !now.Before(*req.NotOnOrAfter):
		return LogoutRequest{}, errors.New("samlsp: logout request has expired")
	case req.NameID == nil || strings.TrimSpace(req.NameID.Value) == "":
		return LogoutRequest{}, errors.New("samlsp: logout request names no NameID")
	}
	out := LogoutRequest{ID: req.ID, Issuer: req.Issuer.Value, NameID: req.NameID.Value}
	if req.SessionIndex != nil {
		out.SessionIndex = req.SessionIndex.Value
	}
	return out, nil
}

// LogoutResponseRedirect answers an IdP-initiated LogoutRequest with a
// Success LogoutResponse over the redirect binding (signed when this SP holds
// a key).
func (p *ServiceProvider) LogoutResponseRedirect(logoutRequestID, relayState string) (string, error) {
	if !p.slo {
		return "", errors.New("samlsp: single logout is not enabled for this service provider")
	}
	u, err := p.sp.MakeRedirectLogoutResponse(logoutRequestID, relayState)
	if err != nil {
		return "", fmt.Errorf("samlsp: logout response: %w", err)
	}
	return u.String(), nil
}

// decodeLogoutMessage returns the XML of a SAML message carried by the redirect
// binding (base64 + DEFLATE in the query) or the POST binding (base64 form).
func decodeLogoutMessage(r *http.Request, param string) ([]byte, error) {
	if data := r.URL.Query().Get(param); data != "" {
		raw, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("samlsp: %s is not base64", param)
		}
		inflated, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), maxLogoutMessageBytes+1))
		if err != nil {
			return nil, fmt.Errorf("samlsp: %s does not inflate", param)
		}
		if len(inflated) > maxLogoutMessageBytes {
			return nil, fmt.Errorf("samlsp: %s is too large", param)
		}
		return inflated, nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	data := r.PostForm.Get(param)
	if data == "" {
		return nil, fmt.Errorf("samlsp: the request carries no %s", param)
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("samlsp: %s is not base64", param)
	}
	if len(raw) > maxLogoutMessageBytes {
		return nil, fmt.Errorf("samlsp: %s is too large", param)
	}
	return raw, nil
}

var whitespace = regexp.MustCompile(`\s+`)

// idpSigningCertificates mirrors the library's IdP signing-certificate lookup:
// every X509 certificate in a KeyDescriptor whose use is "signing" or unset.
func idpSigningCertificates(metadata *saml.EntityDescriptor) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, descriptor := range metadata.IDPSSODescriptors {
		for _, key := range descriptor.KeyDescriptors {
			if key.Use != "" && key.Use != "signing" {
				continue
			}
			for _, certificate := range key.KeyInfo.X509Data.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(whitespace.ReplaceAllString(certificate.Data, ""))
				if err != nil {
					return nil, fmt.Errorf("samlsp: IdP signing certificate is not base64: %w", err)
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, fmt.Errorf("samlsp: parse IdP signing certificate: %w", err)
				}
				certs = append(certs, cert)
			}
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("samlsp: the IdP metadata declares no signing certificate")
	}
	return certs, nil
}

func randomID() []byte {
	b, err := crypto.RandomBytes(20)
	if err != nil {
		panic("samlsp: random source unavailable: " + err.Error())
	}
	return b
}
