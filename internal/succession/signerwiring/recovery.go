// SPDX-License-Identifier: BUSL-1.1

package signerwiring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/recovery"
)

func validRecoveryIdentity(tenantID, identityID string) bool {
	return canonicalTenantUUID(tenantID) && identityID != "" && strings.TrimSpace(identityID) == identityID
}

// PrepareRecoverySuccessor creates or reads back one signer-held, custody-only
// successor and signs the fixed preparation receipt in the same address space.
func (p *ProductionMinter) PrepareRecoverySuccessor(_ context.Context, req signing.RecoveryPrepareRequest) ([]byte, error) {
	p.pairedMu.Lock()
	defer p.pairedMu.Unlock()
	if p.custody == nil || !validRecoveryIdentity(req.TenantID, req.IdentityID) ||
		req.Epoch == 0 || req.Epoch > math.MaxInt64 || req.DeploymentScope == "" ||
		strings.TrimSpace(req.DeploymentScope) != req.DeploymentScope || req.RequestID == "" ||
		strings.TrimSpace(req.RequestID) != req.RequestID {
		return nil, errors.New("invalid recovery preparation identity, scope or epoch")
	}
	handle := succession.TenantKeyHandle(req.TenantID, req.IdentityID, req.Epoch)
	key, err := p.custody.ResolvePredecessor(handle)
	if status.Code(err) == codes.NotFound {
		key, err = p.custody.GenerateSuccessorKey(handle, req.Algorithm)
		if err != nil {
			if existing, readErr := p.custody.ResolvePredecessor(handle); readErr == nil {
				key, err = existing, nil
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("recovery successor custody: %w", err)
	}
	if key.Algorithm() != req.Algorithm {
		return nil, errors.New("recovery successor algorithm differs from requested algorithm")
	}
	receipt := succession.RecoverySuccessorPreparedV1{
		TenantID: req.TenantID, IdentityID: req.IdentityID, Epoch: req.Epoch,
		Algorithm: string(req.Algorithm), Handle: handle, PublicKeyDER: key.Public().DER,
		DeploymentScope: req.DeploymentScope, RequestID: req.RequestID,
	}
	message, err := succession.RecoverySuccessorSigningMessage(receipt)
	if err != nil {
		return nil, err
	}
	receipt.SignerSignature, err = key.Sign(message, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}
	if err := succession.VerifyRecoverySuccessorPrepared(receipt); err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}

// MintRecovery verifies the trust-root-rooted approver authorization before
// signing the fixed recovery commitment with the prepared successor key.
func (p *ProductionMinter) MintRecovery(_ context.Context, req signing.RecoveryMintRequest) ([]byte, error) {
	p.pairedMu.Lock()
	defer p.pairedMu.Unlock()
	if p.custody == nil {
		return nil, errors.New("recovery signer custody unavailable")
	}
	var fields succession.CommitmentFields
	if err := json.Unmarshal(req.CommitmentFieldsJSON, &fields); err != nil {
		return nil, fmt.Errorf("decode recovery commitment: %w", err)
	}
	var auth recovery.RecoveryAuthorization
	if err := json.Unmarshal(req.AuthorizationJSON, &auth); err != nil {
		return nil, fmt.Errorf("decode recovery authorization: %w", err)
	}
	if !validRecoveryIdentity(fields.TenantID, fields.IdentityID) || fields.Epoch == 0 ||
		fields.Epoch > math.MaxInt64 || fields.Epoch != fields.PredecessorEpoch+1 ||
		fields.Epoch != req.HighWaterEpoch+1 || fields.DeploymentScope == "" ||
		fields.CommitmentVersion != 2 || fields.RecordType != succession.RecordType("recovery") ||
		!strings.HasPrefix(fields.PolicyRef, "pcas:recovery:") || len(fields.PolicyRef) == len("pcas:recovery:") ||
		fields.HashAlg != succession.HashAlgSHA256 || auth.Statement.DeploymentScope != fields.DeploymentScope {
		return nil, errors.New("recovery commitment has invalid tenant, epoch, type or policy")
	}
	// Recovery policy's trust root is an operator-configured offline authority,
	// distinct from the signer's PCAS genesis root. The control-plane policy
	// check binds this key to the identity before invoking the signer.
	successor, err := p.custody.ResolvePredecessor(succession.TenantKeyHandle(fields.TenantID, fields.IdentityID, fields.Epoch))
	if err != nil {
		return nil, fmt.Errorf("resolve prepared recovery successor: %w", err)
	}
	if fields.SuccessorAlg != "" && fields.SuccessorAlg != successor.Algorithm() {
		return nil, errors.New("recovery successor algorithm differs from prepared key")
	}
	if len(fields.SuccessorPub) > 0 && !bytes.Equal(fields.SuccessorPub, successor.Public().DER) {
		return nil, errors.New("recovery successor public key differs from prepared key")
	}
	record, err := recovery.Mint(fields, auth, req.TrustRootPublicDER, successor, req.HighWaterEpoch)
	if err != nil {
		return nil, err
	}
	return json.Marshal(record)
}
