// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// AgentRootAnchorStore is a signer-local public trust floor. Its implementation
// lives with AGID; this signer transport does not import the AGID package or a
// database driver. The RPC server holds only the read capability; local
// operator provisioning uses the store's separate write method.
type AgentRootAnchorStore interface {
	ReadAgentRootAnchor(context.Context, string, string) ([]byte, string, error)
}

// ErrAgentRootConflict means a tenant/key already has a different public
// authority. The signer maps this to an explicit conflict while outages remain
// retryable failures.
var ErrAgentRootConflict = errors.New("signing: agent root anchor binding conflicts with first writer")

func WithAgentRootAnchorStore(store AgentRootAnchorStore) ServerOption {
	return func(s *Server) { s.agentRootAnchors = store }
}

func (s *Server) ProvisionAgentRootAnchor(ctx context.Context, req *signerpb.ProvisionAgentRootAnchorRequest) (*signerpb.ProvisionAgentRootAnchorResponse, error) {
	if s == nil || s.agentRootAnchors == nil {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID root-anchor floor is unavailable")
	}
	if req == nil || strings.TrimSpace(req.GetTenantId()) == "" || strings.TrimSpace(req.GetKeyId()) == "" ||
		strings.TrimSpace(req.GetAuthRef()) != req.GetAuthRef() || req.GetAuthRef() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant, root key ID and canonical auth reference are required")
	}
	if err := crypto.ValidatePublicKeyDER(req.GetPublicDer()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "AGID root anchor is not a usable public key")
	}
	publicDER, authRef, err := s.agentRootAnchors.ReadAgentRootAnchor(ctx, req.GetTenantId(), req.GetKeyId())
	if errors.Is(err, os.ErrNotExist) {
		return nil, status.Error(codes.PermissionDenied, "AGID root anchor must be provisioned locally by the signer operator")
	}
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID root-anchor floor is unavailable")
	}
	if !bytes.Equal(publicDER, req.GetPublicDer()) || authRef != req.GetAuthRef() {
		return nil, status.Error(codes.AlreadyExists, "signer AGID root anchor is bound to another authority")
	}
	return &signerpb.ProvisionAgentRootAnchorResponse{PublicDer: publicDER, AuthRef: authRef}, nil
}

func (s *Server) GetAgentRootAnchor(ctx context.Context, req *signerpb.GetAgentRootAnchorRequest) (*signerpb.GetAgentRootAnchorResponse, error) {
	if s == nil || s.agentRootAnchors == nil {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID root-anchor floor is unavailable")
	}
	if req == nil || strings.TrimSpace(req.GetTenantId()) == "" || strings.TrimSpace(req.GetKeyId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant and root key ID are required")
	}
	publicDER, authRef, err := s.agentRootAnchors.ReadAgentRootAnchor(ctx, req.GetTenantId(), req.GetKeyId())
	if errors.Is(err, os.ErrNotExist) {
		return nil, status.Error(codes.NotFound, "signer AGID root anchor is absent")
	}
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID root-anchor floor is unavailable")
	}
	return &signerpb.GetAgentRootAnchorResponse{PublicDer: publicDER, AuthRef: authRef}, nil
}
