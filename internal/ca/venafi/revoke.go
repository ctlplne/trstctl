// SPDX-License-Identifier: BUSL-1.1

package venafi

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto"
)

const revokePath = "/vedsdk/Certificates/Revoke"

var _ catemplate.RevokingBackend = (*backend)(nil)

// Revoke revokes through Venafi's /vedsdk/Certificates/Revoke (A164). Venafi
// addresses the certificate by its SHA-1 thumbprint. The call counts as done
// only when Venafi answers that the certificate is revoked, not merely that a
// revocation was requested: a Venafi policy may hold it for approval.
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
	if err := b.post(ctx, b.cfg.BaseURL+revokePath, map[string]any{
		"Thumbprint": crypto.CertificateSHA1Thumbprint(block.Bytes),
		"Reason":     reason,
		"Comments":   "Revoked through trstctl",
		"Disable":    false,
	}, &out); err != nil {
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
