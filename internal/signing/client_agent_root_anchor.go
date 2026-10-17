// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"errors"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// ProvisionAgentRootAnchor sends public trust material to the isolated signer
// over its authenticated, admission-controlled transport. The signer enforces
// the first-writer fence and returns the exact stored binding.
func (c *Client) ProvisionAgentRootAnchor(ctx context.Context, tenantID, keyID string, publicDER []byte, authRef string) error {
	if c == nil || c.svc == nil {
		return errors.New("signing: signer client is unavailable")
	}
	resp, err := c.svc.ProvisionAgentRootAnchor(ctx, &signerpb.ProvisionAgentRootAnchorRequest{
		TenantId: tenantID, KeyId: keyID, PublicDer: publicDER, AuthRef: authRef,
	})
	if err != nil {
		return err
	}
	if !bytes.Equal(resp.GetPublicDer(), publicDER) || resp.GetAuthRef() != authRef {
		return errors.New("signing: signer root-anchor receipt differs from requested binding")
	}
	return nil
}

// ReadAgentRootAnchor independently reads the current signer-held public floor.
func (c *Client) ReadAgentRootAnchor(ctx context.Context, tenantID, keyID string) ([]byte, string, error) {
	if c == nil || c.svc == nil {
		return nil, "", errors.New("signing: signer client is unavailable")
	}
	resp, err := c.svc.GetAgentRootAnchor(ctx, &signerpb.GetAgentRootAnchorRequest{TenantId: tenantID, KeyId: keyID})
	if err != nil {
		return nil, "", err
	}
	return append([]byte(nil), resp.GetPublicDer()...), resp.GetAuthRef(), nil
}
