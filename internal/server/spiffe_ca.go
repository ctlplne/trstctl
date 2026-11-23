// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// provisionTenantSPIFFECA keeps the Workload API trust root separate from the
// platform CA and from every other tenant. The private key stays in the signer;
// the public certificate is persisted beside the operator's platform CA file.
// A missing half of that pair stops startup rather than silently changing the
// trust root after a restart.
func (s *Server) provisionTenantSPIFFECA(ctx context.Context, c *signing.Client, tenantID string) (crypto.DigestSigner, []byte, error) {
	id, err := uuid.Parse(tenantID)
	if err != nil || id.String() != tenantID {
		return nil, nil, errors.New("server: SPIFFE CA requires a canonical tenant UUID")
	}
	if s.caCertFile == "" || s.store == nil || c == nil {
		return nil, nil, errors.New("server: SPIFFE CA requires signer custody, a store, and an operator-owned CA certificate file")
	}
	handle := "spiffe-x509-ca-" + tenantID
	certFile := s.caCertFile + ".spiffe-" + tenantID
	var signer crypto.DigestSigner
	var certDER []byte
	err = s.store.WithCAProvisionLock(ctx, func(ctx context.Context) error {
		var persisted []byte
		raw, readErr := os.ReadFile(certFile) // #nosec G304 -- path derives from operator CA file and canonical tenant UUID
		switch {
		case readErr == nil:
			block, rest := pem.Decode(raw)
			if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
				return fmt.Errorf("server: SPIFFE CA certificate %q is invalid; restore the certificate matching signer handle %q", certFile, handle)
			}
			persisted = block.Bytes
		case errors.Is(readErr, os.ErrNotExist):
		default:
			return fmt.Errorf("server: read SPIFFE CA certificate %q: %w", certFile, readErr)
		}
		remote, handleErr := s.signerForPrivilegedHandle(ctx, c, handle, signing.PurposeCASign)
		if handleErr == nil && len(persisted) > 0 {
			if err := crypto.VerifyCertificateSigner(persisted, remote.Public()); err != nil {
				return fmt.Errorf("server: SPIFFE CA certificate does not match signer handle %q: %w", handle, err)
			}
			signer, certDER = remote, persisted
			return nil
		}
		if handleErr != nil && status.Code(handleErr) != codes.NotFound {
			return fmt.Errorf("server: inspect SPIFFE CA signer handle %q: %w", handle, handleErr)
		}
		if handleErr == nil {
			return fmt.Errorf("server: SPIFFE CA signer handle %q exists without certificate %q; restore the certificate", handle, certFile)
		}
		if len(persisted) > 0 {
			return fmt.Errorf("server: SPIFFE CA certificate %q exists without signer handle %q; restore signer custody", certFile, handle)
		}
		remote, err = s.generatePrivilegedKeyHandle(ctx, c, crypto.ECDSAP256, handle,
			[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign)
		if err != nil {
			return fmt.Errorf("server: generate tenant SPIFFE CA key: %w", err)
		}
		issued, err := crypto.SelfSignedCACert(remote, "trstctl SPIFFE CA "+tenantID, 90*24*time.Hour)
		if err != nil {
			return fmt.Errorf("server: self-sign tenant SPIFFE CA: %w", err)
		}
		if err := writeCertPEM(certFile, issued); err != nil {
			return fmt.Errorf("server: persist tenant SPIFFE CA certificate: %w", err)
		}
		signer, certDER = remote, issued
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return signer, certDER, nil
}
