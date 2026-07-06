// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// SuccessionMinter is a generic successor-minting extension attached to the AN-4
// signer. The core defines only this generic seam; the concrete succession
// semantics — commitment forming, dual-signing, and epoch discipline — live in an
// edition implementation attached via WithSuccessionMinter. The core-only build
// attaches none and mints no successions. The interface names nothing
// edition-specific: it takes a generic minting request and returns a generic
// result whose record body is opaque to core.
type SuccessionMinter interface {
	MintSuccessor(ctx context.Context, req MintRequest) (MintResult, error)
}

// MintRequest is the generic successor-minting request. It carries NO private key
// material: the predecessor key is referenced only by an opaque in-signer handle,
// so the request that crosses into the minter never contains a private key.
type MintRequest struct {
	IdentityID               string
	TenantID                 string
	DeploymentScope          string
	PredecessorHandle        string
	AssertedPredecessorEpoch uint64
	TargetAlgorithm          crypto.Algorithm
	PolicyRef                string
	PolicyDecision           []byte // signed policy artifact (optional)
	Authorization            []byte // dual-control authorization token (optional)
	BreakGlass               []byte // strength-downgrade break-glass token (optional)
	Attestation              []byte // successor-custodian attestation evidence (optional; PCAS-29)
	NotBefore                int64
	NotAfter                 int64
}

// MintResult is the generic successor-minting result. It carries only public
// material — the successor public key and the opaque encoded record — so no
// private key crosses the boundary.
type MintResult struct {
	Epoch              uint64
	SuccessorAlgorithm crypto.Algorithm
	SuccessorPublicDER []byte
	EncodedRecord      []byte
}

// ErrNoMinter is returned when no successor minter is attached (core-only build).
var ErrNoMinter = errors.New("signing: no successor minter attached")

// WithSuccessionMinter attaches a successor minter to the signer, beside
// WithKeyFactory. The core names only the generic seam; the edition supplies the
// implementation without importing ee/ into core.
func WithSuccessionMinter(m SuccessionMinter) ServerOption {
	return func(s *Server) {
		if m != nil {
			s.minter = m
		}
	}
}

// mintSuccessor dispatches to the attached minter, failing closed when none is
// attached. It is the in-process Go entry point; the exported gRPC handler
// Server.MintSuccessor (server.go, satisfying signerpb.SignerServiceServer) calls
// it after decoding the wire request, so the same custody discipline applies
// whether a mint arrives in-process or over the transport (INT-01).
func (s *Server) mintSuccessor(ctx context.Context, req MintRequest) (MintResult, error) {
	s.mu.Lock()
	m := s.minter
	s.mu.Unlock()
	if m == nil {
		return MintResult{}, ErrNoMinter
	}
	return m.MintSuccessor(ctx, req)
}

// MintSuccessor is the gRPC handler that satisfies signerpb.SignerServiceServer
// (INT-01). It decodes the wire request, dispatches to the attached minter inside
// the signer, and returns only public material — the successor public key and the
// opaque encoded record. It fails closed with UNIMPLEMENTED when no minter is
// attached (core-only or unlicensed signer). No private key crosses the boundary:
// the control plane can request a succession over this RPC but cannot forge one,
// because it never obtains the key material (claims 1/12/49).
func (s *Server) MintSuccessor(ctx context.Context, req *signerpb.MintSuccessorRequest) (*signerpb.MintSuccessorResponse, error) {
	mreq, err := mintRequestFromProto(req)
	if err != nil {
		return nil, err
	}
	res, err := s.mintSuccessor(ctx, mreq)
	if err != nil {
		if errors.Is(err, ErrNoMinter) {
			return nil, status.Error(codes.Unimplemented, err.Error())
		}
		// The minter's typed refusals (epoch/strength/policy/attestation/dual-control)
		// are precondition failures the caller can inspect via the status message.
		return nil, status.Errorf(codes.FailedPrecondition, "mint successor: %v", err)
	}
	return mintResultToProto(res), nil
}
