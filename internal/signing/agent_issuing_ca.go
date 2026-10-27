// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// IssuingCAProvider is implemented by an issuance key op that certifies a
// tenant's agent credentials under a signer-held issuing CA and can publish
// that CA's certificate so the tenant's relying services can pin it.
type IssuingCAProvider interface {
	IssuingCACertificate(tenantID string) ([]byte, error)
}

// GetAgentIssuingCA returns the certificate of the tenant's agent issuing CA.
// The certificate is public material; the CA key never leaves the signer.
func (s *Server) GetAgentIssuingCA(_ context.Context, req *signerpb.GetAgentIssuingCARequest) (*signerpb.GetAgentIssuingCAResponse, error) {
	tenantID := strings.TrimSpace(req.GetTenantId())
	if tenantID == "" || tenantID != req.GetTenantId() {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	s.mu.Lock()
	op := s.issuanceKeyOp
	s.mu.Unlock()
	provider, ok := op.(IssuingCAProvider)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "signer agent credential issuance is not attached")
	}
	der, err := provider.IssuingCACertificate(tenantID)
	if err != nil || len(der) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "signer agent issuing CA is unavailable")
	}
	return &signerpb.GetAgentIssuingCAResponse{CertificateDer: der}, nil
}

// AgentIssuingCA reads the certificate of the tenant's agent issuing CA from
// the signer.
func (c *Client) AgentIssuingCA(ctx context.Context, tenantID string) ([]byte, error) {
	if c == nil || c.svc == nil {
		return nil, errors.New("signing: signer client is unavailable")
	}
	resp, err := c.svc.GetAgentIssuingCA(ctx, &signerpb.GetAgentIssuingCARequest{TenantId: tenantID})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), resp.GetCertificateDer()...), nil
}
