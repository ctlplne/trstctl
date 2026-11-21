// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// RecoveryPrepareRequest carries public identity facts. The attached PCAS
// minter derives the handle and signs the receipt inside the signer.
type RecoveryPrepareRequest struct {
	TenantID, IdentityID, DeploymentScope, RequestID string
	Epoch                                            uint64
	Algorithm                                        crypto.Algorithm
}

type RecoveryMintRequest struct {
	CommitmentFieldsJSON, AuthorizationJSON, TrustRootPublicDER []byte
	HighWaterEpoch                                              uint64
}

type RecoveryMinter interface {
	PrepareRecoverySuccessor(context.Context, RecoveryPrepareRequest) ([]byte, error)
	MintRecovery(context.Context, RecoveryMintRequest) ([]byte, error)
}

func (s *Server) PrepareRecoverySuccessor(ctx context.Context, req *signerpb.PrepareRecoverySuccessorRequest) (*signerpb.PrepareRecoverySuccessorResponse, error) {
	if req == nil || req.GetTenantId() == "" || req.GetIdentityId() == "" || req.GetDeploymentScope() == "" || req.GetRequestId() == "" || req.GetEpoch() == 0 ||
		len(req.GetTenantId()) > 64 || len(req.GetIdentityId()) > 2048 || len(req.GetDeploymentScope()) > 2048 || len(req.GetRequestId()) > 128 {
		return nil, status.Error(codes.InvalidArgument, "incomplete or oversized recovery preparation")
	}
	alg, err := algorithmFromProto(req.GetAlgorithm())
	if err != nil {
		return nil, err
	}
	minter, ok := s.minter.(RecoveryMinter)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "recovery minter unavailable")
	}
	encoded, err := minter.PrepareRecoverySuccessor(ctx, RecoveryPrepareRequest{
		TenantID: req.GetTenantId(), IdentityID: req.GetIdentityId(), DeploymentScope: req.GetDeploymentScope(),
		RequestID: req.GetRequestId(), Epoch: req.GetEpoch(), Algorithm: alg,
	})
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "prepare recovery successor: %v", err)
	}
	return &signerpb.PrepareRecoverySuccessorResponse{EncodedReceipt: encoded}, nil
}

func (s *Server) MintRecovery(ctx context.Context, req *signerpb.MintRecoveryRequest) (*signerpb.MintRecoveryResponse, error) {
	if req == nil || len(req.GetCommitmentFieldsJson()) == 0 || len(req.GetAuthorizationJson()) == 0 || len(req.GetTrustRootPublicDer()) == 0 ||
		len(req.GetCommitmentFieldsJson()) > 64*1024 || len(req.GetAuthorizationJson()) > 256*1024 || len(req.GetTrustRootPublicDer()) > 16*1024 {
		return nil, status.Error(codes.InvalidArgument, "incomplete or oversized recovery mint")
	}
	minter, ok := s.minter.(RecoveryMinter)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "recovery minter unavailable")
	}
	encoded, err := minter.MintRecovery(ctx, RecoveryMintRequest{
		CommitmentFieldsJSON: req.GetCommitmentFieldsJson(), AuthorizationJSON: req.GetAuthorizationJson(),
		TrustRootPublicDER: req.GetTrustRootPublicDer(), HighWaterEpoch: req.GetHighWaterEpoch(),
	})
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "mint recovery: %v", err)
	}
	return &signerpb.MintRecoveryResponse{EncodedRecord: encoded}, nil
}
