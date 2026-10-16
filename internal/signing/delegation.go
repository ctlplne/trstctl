// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"encoding/json"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
	"trstctl.com/trstctl/internal/succession/delegation"
)

const delegationReceiptHandle = "pcas:delegation:receipt:v1"

// DelegationStore is signer-owned PCAS constraint state. Core signer transport
// exposes only a narrow command; the concrete tree stays in the core family.
type DelegationStore interface {
	Apply(delegation.Command, func(string, []byte) ([]byte, []byte, error)) (delegation.Receipt, error)
}

func WithDelegationStore(store DelegationStore) ServerOption {
	return func(s *Server) { s.delegationStore = store }
}

// ApplyDelegation commits a tenant scope and a signer-signed receipt inside the
// isolated process. Sign's operation journal makes a lost response retry exact.
func (s *Server) ApplyDelegation(ctx context.Context, req *signerpb.ApplyDelegationRequest) (*signerpb.ApplyDelegationResponse, error) {
	if req == nil || req.GetTenantId() == "" || req.GetOperationId() == "" || req.GetScopeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "delegation tenant, operation and scope are required")
	}
	if s.delegationStore == nil || s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "persistent signer delegation custody unavailable")
	}
	command := delegation.Command{
		TenantID: req.GetTenantId(), OperationID: req.GetOperationId(),
		Kind: req.GetKind(), ScopeID: req.GetScopeId(), ParentScopeID: req.GetParentScopeId(),
		EpochFloor: req.GetEpochFloor(),
	}
	receipt, err := s.delegationStore.Apply(command, func(operationID string, body []byte) ([]byte, []byte, error) {
		key := &signerpb.KeyHandle{Id: delegationReceiptHandle}
		public, keyErr := s.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: key})
		if status.Code(keyErr) == codes.NotFound {
			_, keyErr = s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
				RequestedId: delegationReceiptHandle, Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
				AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_AUDIT_EVIDENCE},
				AllowedHashes:   []signerpb.Hash{signerpb.Hash_HASH_SHA256},
			})
			if keyErr == nil || status.Code(keyErr) == codes.AlreadyExists {
				public, keyErr = s.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: key})
			}
		}
		if keyErr != nil {
			return nil, nil, keyErr
		}
		if public.GetAlgorithm() != signerpb.Algorithm_ALGORITHM_ECDSA_P256 {
			return nil, nil, errors.New("delegation receipt key algorithm mismatch")
		}
		signed, signErr := s.Sign(ctx, &signerpb.SignRequest{
			Handle: key, Digest: crypto.SHA256Sum(body), Hash: signerpb.Hash_HASH_SHA256,
			Purpose:     signerpb.KeyPurpose_KEY_PURPOSE_AUDIT_EVIDENCE,
			OperationId: "pcas-delegation-receipt:" + command.TenantID + ":" + operationID,
		})
		if signErr != nil {
			return nil, nil, signErr
		}
		return public.GetPublicKey(), signed.GetSignature(), nil
	})
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "apply delegation: %v", err)
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode delegation receipt: %v", err)
	}
	return &signerpb.ApplyDelegationResponse{SignedReceiptJson: data}, nil
}

func (c *Client) ApplyDelegation(ctx context.Context, cmd delegation.Command) (delegation.Receipt, error) {
	resp, err := c.svc.ApplyDelegation(ctx, &signerpb.ApplyDelegationRequest{
		TenantId: cmd.TenantID, OperationId: cmd.OperationID,
		Kind: cmd.Kind, ScopeId: cmd.ScopeID, ParentScopeId: cmd.ParentScopeID,
		EpochFloor: cmd.EpochFloor,
	})
	if err != nil {
		return delegation.Receipt{}, err
	}
	var receipt delegation.Receipt
	if err := json.Unmarshal(resp.GetSignedReceiptJson(), &receipt); err != nil {
		return delegation.Receipt{}, err
	}
	if receipt.Command != cmd {
		return delegation.Receipt{}, errors.New("signing: delegation receipt does not bind command")
	}
	if err := receipt.Verify(); err != nil {
		return delegation.Receipt{}, err
	}
	return receipt, nil
}
