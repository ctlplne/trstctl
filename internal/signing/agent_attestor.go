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

// AgentAttestorStore is the signer-local public attestation trust floor. Each
// attestor public key is bound to one tenant, one key ID and one attestation
// method; the gate verifies a tenant's attestation evidence only against that
// tenant's attestors. Its implementation lives with AGID, so this transport
// imports neither the AGID package nor a database driver. An exact retry is
// safe; a changed binding must be refused by the store itself.
type AgentAttestorStore interface {
	ProvisionAgentAttestor(context.Context, string, string, []byte, string) error
	ReadAgentAttestor(context.Context, string, string) ([]byte, string, error)
}

// ErrAgentAttestorConflict means a tenant/key already binds a different public
// key or method. ErrAgentAttestorInvalid means the store refused the binding
// itself (an unknown method or a key ID it cannot store). Outages stay
// retryable failures.
var (
	ErrAgentAttestorConflict = errors.New("signing: agent attestor binding conflicts with first writer")
	ErrAgentAttestorInvalid  = errors.New("signing: agent attestor binding is invalid")
)

func WithAgentAttestorStore(store AgentAttestorStore) ServerOption {
	return func(s *Server) { s.agentAttestors = store }
}

func canonicalField(v string) bool { return v != "" && strings.TrimSpace(v) == v }

func (s *Server) ProvisionAgentAttestor(ctx context.Context, req *signerpb.ProvisionAgentAttestorRequest) (*signerpb.ProvisionAgentAttestorResponse, error) {
	if s == nil || s.agentAttestors == nil {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID attestor floor is unavailable")
	}
	if req == nil || !canonicalField(req.GetTenantId()) || !canonicalField(req.GetKeyId()) || !canonicalField(req.GetMethod()) {
		return nil, status.Error(codes.InvalidArgument, "tenant, attestor key ID and canonical attestation method are required")
	}
	if err := crypto.ValidatePublicKeyDER(req.GetPublicDer()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "AGID attestor key is not a usable public key")
	}
	if err := s.agentAttestors.ProvisionAgentAttestor(ctx, req.GetTenantId(), req.GetKeyId(), req.GetPublicDer(), req.GetMethod()); err != nil {
		switch {
		case errors.Is(err, ErrAgentAttestorConflict):
			return nil, status.Error(codes.AlreadyExists, "signer AGID attestor key ID is bound to another key or method")
		case errors.Is(err, ErrAgentAttestorInvalid):
			return nil, status.Error(codes.InvalidArgument, "signer refused the AGID attestor key ID or method")
		}
		return nil, status.Error(codes.FailedPrecondition, "signer AGID attestor floor is unavailable")
	}
	publicDER, method, err := s.agentAttestors.ReadAgentAttestor(ctx, req.GetTenantId(), req.GetKeyId())
	if err != nil || !bytes.Equal(publicDER, req.GetPublicDer()) || method != req.GetMethod() {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID attestor readback differs from requested binding")
	}
	return &signerpb.ProvisionAgentAttestorResponse{PublicDer: publicDER, Method: method}, nil
}

func (s *Server) GetAgentAttestor(ctx context.Context, req *signerpb.GetAgentAttestorRequest) (*signerpb.GetAgentAttestorResponse, error) {
	if s == nil || s.agentAttestors == nil {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID attestor floor is unavailable")
	}
	if req == nil || !canonicalField(req.GetTenantId()) || !canonicalField(req.GetKeyId()) {
		return nil, status.Error(codes.InvalidArgument, "tenant and attestor key ID are required")
	}
	publicDER, method, err := s.agentAttestors.ReadAgentAttestor(ctx, req.GetTenantId(), req.GetKeyId())
	if errors.Is(err, os.ErrNotExist) {
		return nil, status.Error(codes.NotFound, "signer AGID attestor is absent")
	}
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "signer AGID attestor floor is unavailable")
	}
	return &signerpb.GetAgentAttestorResponse{PublicDer: publicDER, Method: method}, nil
}
