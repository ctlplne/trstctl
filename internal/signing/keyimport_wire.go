// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func keyImportPolicyProto(policy crypto.KeyImportPolicy) *signerpb.KeyImportPolicyV2 {
	purposes := make([]signerpb.KeyPurpose, len(policy.AllowedPurposes))
	for i, purpose := range policy.AllowedPurposes {
		purposes[i] = signerpb.KeyPurpose(purpose)
	}
	hashes := make([]signerpb.Hash, len(policy.AllowedHashes))
	for i, hash := range policy.AllowedHashes {
		hashes[i] = signerpb.Hash(hash)
	}
	return &signerpb.KeyImportPolicyV2{
		TenantId: policy.TenantID, OperationId: policy.OperationID, RequestedId: policy.Handle,
		ExpectedPublicKey: policy.ExpectedPublicKey, AllowedPurposes: purposes, AllowedHashes: hashes,
		RequireAuthorization: policy.RequireAuthorization,
	}
}

func keyImportPolicyFromProto(policy *signerpb.KeyImportPolicyV2) crypto.KeyImportPolicy {
	purposes := make([]int32, len(policy.GetAllowedPurposes()))
	for i, purpose := range policy.GetAllowedPurposes() {
		purposes[i] = int32(purpose)
	}
	hashes := make([]int32, len(policy.GetAllowedHashes()))
	for i, hash := range policy.GetAllowedHashes() {
		hashes[i] = int32(hash)
	}
	return crypto.KeyImportPolicy{
		TenantID: policy.GetTenantId(), OperationID: policy.GetOperationId(), Handle: policy.GetRequestedId(),
		ExpectedPublicKey: policy.GetExpectedPublicKey(), AllowedPurposes: purposes, AllowedHashes: hashes,
		RequireAuthorization: policy.GetRequireAuthorization(),
	}
}

func prepareKeyImportProto(offer crypto.AuthenticatedKeyImportOffer) *signerpb.PrepareKeyImportV2Response {
	return &signerpb.PrepareKeyImportV2Response{
		Version: offer.Version, Suite: offer.Suite, Policy: keyImportPolicyProto(offer.KeyImportPolicy),
		PublicKey: offer.PublicKey, IssuedAtUnix: offer.IssuedAt, ExpiresAtUnix: offer.ExpiresAt,
		SignerPublicKey: offer.SignerPublicKey, Signature: offer.Signature,
	}
}
