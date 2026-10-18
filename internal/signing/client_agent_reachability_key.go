// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"errors"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// ProvisionAgentReachabilityKey sends only a public key over the authenticated
// signer channel and verifies the signer's exact durable readback.
func (c *Client) ProvisionAgentReachabilityKey(ctx context.Context, keyID string, publicDER []byte) error {
	if c == nil || c.svc == nil {
		return errors.New("signing: signer client is unavailable")
	}
	resp, err := c.svc.ProvisionAgentReachabilityKey(ctx, &signerpb.ProvisionAgentReachabilityKeyRequest{KeyId: keyID, PublicDer: publicDER})
	if err != nil {
		return err
	}
	if !bytes.Equal(resp.GetPublicDer(), publicDER) {
		return errors.New("signing: signer verdict-key receipt differs from requested binding")
	}
	return nil
}

func (c *Client) ReadAgentReachabilityKey(ctx context.Context, keyID string) ([]byte, error) {
	if c == nil || c.svc == nil {
		return nil, errors.New("signing: signer client is unavailable")
	}
	resp, err := c.svc.GetAgentReachabilityKey(ctx, &signerpb.GetAgentReachabilityKeyRequest{KeyId: keyID})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), resp.GetPublicDer()...), nil
}
