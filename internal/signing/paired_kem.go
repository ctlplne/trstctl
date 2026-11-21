// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// PairedKEMMintRequest contains only public PCAS identity and algorithm facts.
// The signer derives the key handles, commitment, and all bytes it signs.
type PairedKEMMintRequest struct {
	TenantID, IdentityID, RequestID string
	PredecessorEpoch                uint64
	SigningAlgorithm                crypto.Algorithm
	KEMAlgorithm                    KEMAlgorithm
}

// PairedKEMMinter is an optional signer-local PCAS ceremony. It returns a
// public, verifiable record and never exposes a signing or KEM private key.
type PairedKEMMinter interface {
	MintPairedKEM(context.Context, PairedKEMMintRequest) ([]byte, error)
}

// MintPairedKEM is a typed alternative to generic Sign for a paired KEM
// successor. An attached minter checks the identity/epoch handles and forms
// the commitment inside signer custody; callers cannot submit a digest.
func (s *Server) MintPairedKEM(ctx context.Context, req *signerpb.MintPairedKEMRequest) (*signerpb.MintPairedKEMResponse, error) {
	if req == nil || req.GetTenantId() == "" || req.GetIdentityId() == "" || req.GetRequestId() == "" ||
		len(req.GetTenantId()) > 64 || len(req.GetIdentityId()) > 2048 || len(req.GetRequestId()) > 128 {
		return nil, status.Error(codes.InvalidArgument, "incomplete or oversized paired KEM request")
	}
	algorithm, err := algorithmFromProto(req.GetSigningAlgorithm())
	if err != nil {
		return nil, err
	}
	if req.GetKemAlgorithm() == signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "missing paired KEM algorithm")
	}
	s.mu.Lock()
	minter, ok := s.minter.(PairedKEMMinter)
	s.mu.Unlock()
	if !ok {
		return nil, status.Error(codes.Unimplemented, "paired KEM minter is unavailable")
	}
	record, err := minter.MintPairedKEM(ctx, PairedKEMMintRequest{
		TenantID: req.GetTenantId(), IdentityID: req.GetIdentityId(), RequestID: req.GetRequestId(),
		PredecessorEpoch: req.GetPredecessorEpoch(), SigningAlgorithm: algorithm,
		KEMAlgorithm: req.GetKemAlgorithm(),
	})
	if err != nil {
		if errors.Is(err, ErrNoKEMCustody) {
			return nil, status.Error(codes.Unimplemented, err.Error())
		}
		return nil, status.Errorf(codes.FailedPrecondition, "mint paired KEM: %v", err)
	}
	if len(record) == 0 {
		return nil, status.Error(codes.Internal, "paired KEM minter returned no record")
	}
	return &signerpb.MintPairedKEMResponse{EncodedRecord: record}, nil
}
