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
// database driver. An exact retry is safe, and a changed tenant/key binding
// must be refused by the store itself.
type AgentRootAnchorStore interface {
	ProvisionAgentRootAnchor(context.Context, string, string, []byte, string) error
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
	if err := s.agentRootAnchors.ProvisionAgentRootAnchor(ctx, req.GetTenantId(), req.GetKeyId(), req.GetPublicDer(), req.GetAuthRef()); err != nil {
		if errors.Is(err, ErrAgentRootConflict) {
			return nil, status.Error(codes.AlreadyExists, "signer AGID root anchor is bound to another authority")
		}
		return nil, status.Error(codes.FailedPrecondition, "signer AGID root anchor conflicts with retained authority or its floor is unavailable")
	}
	publicDER, authRef, err := s.agentRootAnchors.ReadAgentRootAnchor(ctx, req.GetTenantId(), req.GetKeyId())
	if err != nil || !bytes.Equal(publicDER, req.GetPublicDer()) || authRef != req.GetAuthRef() {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID root-anchor readback differs from requested authority")
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
