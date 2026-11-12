// SPDX-License-Identifier: BUSL-1.1

package venafi

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	revokePath = "/vedsdk/Certificates/Revoke"
	// searchPath is GET Certificates, the certificate search (OD-7).
	searchPath = "/vedsdk/Certificates/"
)

var _ catemplate.RevokingBackend = (*backend)(nil)

// Revoke revokes through Venafi's /vedsdk/Certificates/Revoke (A164). Venafi
// addresses the certificate by its SHA-1 thumbprint, or (OD-7, RevokeBy
// certificate_dn) by the DN of the certificate object that holds it, for a
// policy that revokes only by DN. The call counts as done only when Venafi
// answers that the certificate is revoked, not merely that a revocation was
// requested: a Venafi policy may hold it for approval.
func (b *backend) Revoke(ctx context.Context, req ca.RevokeRequest) error {
	block, _ := pem.Decode(req.CertificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("venafi: revocation needs the certificate; none supplied")
	}
	if err := b.validateEndpoint(); err != nil {
		return err
	}
	// Venafi takes RFC 5280 reasons 0 to 5; any other reason is recorded there
	// as unspecified rather than failing the revocation, and trstctl's own
	// event keeps the precise one.
	reason := req.ReasonCode
	if reason < 0 || reason > 5 {
		reason = 0
	}
	var out struct {
		Success   bool   `json:"Success"`
		Requested bool   `json:"Requested"`
		Revoked   bool   `json:"Revoked"`
		Error     string `json:"Error"`
	}
	thumbprint := crypto.CertificateSHA1Thumbprint(block.Bytes)
	body := map[string]any{
		"Thumbprint": thumbprint,
		"Reason":     reason,
		"Comments":   "Revoked through trstctl",
		"Disable":    false,
	}
	if b.cfg.RevokeBy == RevokeByCertificateDN {
		dn, err := b.certificateDN(ctx, thumbprint)
		if err != nil {
			return err
		}
		delete(body, "Thumbprint")
		body["CertificateDN"] = dn
	}
	if err := b.post(ctx, b.cfg.BaseURL+revokePath, body, &out); err != nil {
		return fmt.Errorf("venafi: revoke: %w", err)
	}
	switch {
	case out.Revoked:
		return nil
	case out.Success && out.Requested:
		return errors.New("venafi: revocation was requested but Venafi has not revoked the certificate yet; it may be waiting for approval")
	default:
		return errors.New("venafi: revocation was refused")
	}
}

// certificateDN finds the DN of the one certificate object whose current
// certificate has this SHA-1 thumbprint (GET Certificates?Thumbprint=, OD-7).
// Revoking by DN revokes the object's current certificate, so an object that
// has moved on to another certificate is not revoked in its place: the
// search's answer must name this thumbprint as the object's own.
func (b *backend) certificateDN(ctx context.Context, thumbprint string) (string, error) {
	var out struct {
		Certificates []struct {
			DN   string `json:"DN"`
			X509 struct {
				Thumbprint string `json:"Thumbprint"`
			} `json:"X509"`
		} `json:"Certificates"`
	}
	query := url.Values{"Thumbprint": {thumbprint}, "Limit": {"2"}}
	if err := b.get(ctx, b.cfg.BaseURL+searchPath+"?"+query.Encode(), &out); err != nil {
		return "", fmt.Errorf("venafi: find the certificate object: %w", err)
	}
	var dns []string
	for _, c := range out.Certificates {
		if strings.EqualFold(c.X509.Thumbprint, thumbprint) && strings.TrimSpace(c.DN) != "" {
			dns = append(dns, c.DN)
		}
	}
	switch len(dns) {
	case 1:
		return dns[0], nil
	case 0:
		return "", errors.New("venafi: no certificate object holds this certificate as its current one; it may have been renewed or removed in Venafi")
	default:
		return "", errors.New("venafi: more than one certificate object holds this certificate; revoke it in Venafi")
	}
}
