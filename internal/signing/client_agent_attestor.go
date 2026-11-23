// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"errors"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// ProvisionAgentAttestor confirms an exact operator-installed tenant attestor
// over the authenticated transport. The RPC cannot add or replace trust.
func (c *Client) ProvisionAgentAttestor(ctx context.Context, tenantID, keyID string, publicDER []byte, method string) error {
	if c == nil || c.svc == nil {
		return errors.New("signing: signer client is unavailable")
	}
	resp, err := c.svc.ProvisionAgentAttestor(ctx, &signerpb.ProvisionAgentAttestorRequest{
		TenantId: tenantID, KeyId: keyID, PublicDer: publicDER, Method: method,
	})
	if err != nil {
		return err
	}
	if !bytes.Equal(resp.GetPublicDer(), publicDER) || resp.GetMethod() != method {
		return errors.New("signing: signer attestor receipt differs from requested binding")
	}
	return nil
}

// ReadAgentAttestor independently reads one tenant attestor from the signer's
// public floor.
func (c *Client) ReadAgentAttestor(ctx context.Context, tenantID, keyID string) ([]byte, string, error) {
	if c == nil || c.svc == nil {
		return nil, "", errors.New("signing: signer client is unavailable")
	}
	resp, err := c.svc.GetAgentAttestor(ctx, &signerpb.GetAgentAttestorRequest{TenantId: tenantID, KeyId: keyID})
	if err != nil {
		return nil, "", err
	}
	return append([]byte(nil), resp.GetPublicDer()...), resp.GetMethod(), nil
}
