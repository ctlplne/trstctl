package server

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const ocspResponderHandlePrefix = "ocsp-responder-"

// provisionOCSPResponderSigner returns the stable signer-held key used by the
// delegated OCSP responder for caID. The key is not a CA key: the CA authorizes it
// by signing an OCSPSigning-only responder certificate, and the signer only ever
// exposes digest signing through its separate process boundary (AN-4).
func (s *Server) provisionOCSPResponderSigner(ctx context.Context, c *signing.Client, caID string) (crypto.DigestSigner, error) {
	if c == nil {
		return nil, fmt.Errorf("signer unavailable")
	}
	handle := ocspResponderHandlePrefix + caID
	if remote, err := c.SignerForHandleWithPurpose(ctx, handle, signing.PurposeGeneric); err == nil {
		return remote, nil
	}
	generated, err := c.GenerateConstrainedKeyHandle(ctx, crypto.ECDSAP256, handle,
		[]signing.KeyPurpose{signing.PurposeGeneric}, signing.PurposeGeneric)
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			return c.SignerForHandleWithPurpose(ctx, handle, signing.PurposeGeneric)
		}
		return nil, err
	}
	return generated, nil
}
