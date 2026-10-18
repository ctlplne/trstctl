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

// AgentReachabilityKeyStore owns only public verdict trust. The signer reads it
// locally and never accepts a verdict key from a GatedIssue request.
type AgentReachabilityKeyStore interface {
	PutVerdictSigner(context.Context, string, []byte) error
	ReadVerdictSigner(context.Context, string) ([]byte, error)
}

var ErrAgentReachabilityConflict = errors.New("signing: AGID reachability key conflicts with first writer")

func WithAgentReachabilityKeyStore(store AgentReachabilityKeyStore) ServerOption {
	return func(s *Server) { s.agentReachabilityKeys = store }
}

func (s *Server) ProvisionAgentReachabilityKey(ctx context.Context, req *signerpb.ProvisionAgentReachabilityKeyRequest) (*signerpb.ProvisionAgentReachabilityKeyResponse, error) {
	if s == nil || s.agentReachabilityKeys == nil {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID reachability trust floor is unavailable")
	}
	if req == nil || req.GetKeyId() == "" || strings.TrimSpace(req.GetKeyId()) != req.GetKeyId() {
		return nil, status.Error(codes.InvalidArgument, "canonical verdict key ID is required")
	}
	if err := crypto.ValidatePublicKeyDER(req.GetPublicDer()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "AGID verdict key is not a usable public key")
	}
	if err := s.agentReachabilityKeys.PutVerdictSigner(ctx, req.GetKeyId(), req.GetPublicDer()); err != nil {
		if errors.Is(err, ErrAgentReachabilityConflict) {
			return nil, status.Error(codes.AlreadyExists, "signer AGID verdict key is bound to another authority")
		}
		return nil, status.Error(codes.FailedPrecondition, "signer AGID reachability trust floor is unavailable")
	}
	stored, err := s.agentReachabilityKeys.ReadVerdictSigner(ctx, req.GetKeyId())
	if err != nil || !bytes.Equal(stored, req.GetPublicDer()) {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID verdict key readback differs from requested authority")
	}
	return &signerpb.ProvisionAgentReachabilityKeyResponse{PublicDer: stored}, nil
}

func (s *Server) GetAgentReachabilityKey(ctx context.Context, req *signerpb.GetAgentReachabilityKeyRequest) (*signerpb.GetAgentReachabilityKeyResponse, error) {
	if s == nil || s.agentReachabilityKeys == nil {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID reachability trust floor is unavailable")
	}
	if req == nil || req.GetKeyId() == "" || strings.TrimSpace(req.GetKeyId()) != req.GetKeyId() {
		return nil, status.Error(codes.InvalidArgument, "canonical verdict key ID is required")
	}
	stored, err := s.agentReachabilityKeys.ReadVerdictSigner(ctx, req.GetKeyId())
	if errors.Is(err, os.ErrNotExist) {
		return nil, status.Error(codes.NotFound, "signer AGID verdict key is absent")
	}
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID reachability trust floor is unavailable")
	}
	return &signerpb.GetAgentReachabilityKeyResponse{PublicDer: stored}, nil
}
