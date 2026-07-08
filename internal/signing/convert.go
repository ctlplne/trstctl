// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// maxDigestLen bounds an accepted digest (SHA-512 is 64 bytes).
const maxDigestLen = 64

func algorithmFromProto(a signerpb.Algorithm) (crypto.Algorithm, error) {
	switch a {
	case signerpb.Algorithm_ALGORITHM_RSA_2048:
		return crypto.RSA2048, nil
	case signerpb.Algorithm_ALGORITHM_RSA_3072:
		return crypto.RSA3072, nil
	case signerpb.Algorithm_ALGORITHM_RSA_4096:
		return crypto.RSA4096, nil
	case signerpb.Algorithm_ALGORITHM_ECDSA_P256:
		return crypto.ECDSAP256, nil
	case signerpb.Algorithm_ALGORITHM_ECDSA_P384:
		return crypto.ECDSAP384, nil
	case signerpb.Algorithm_ALGORITHM_ECDSA_P521:
		return crypto.ECDSAP521, nil
	default:
		return "", status.Errorf(codes.InvalidArgument, "unsupported algorithm %v", a)
	}
}

func algorithmToProto(a crypto.Algorithm) signerpb.Algorithm {
	switch a {
	case crypto.RSA2048:
		return signerpb.Algorithm_ALGORITHM_RSA_2048
	case crypto.RSA3072:
		return signerpb.Algorithm_ALGORITHM_RSA_3072
	case crypto.RSA4096:
		return signerpb.Algorithm_ALGORITHM_RSA_4096
	case crypto.ECDSAP256:
		return signerpb.Algorithm_ALGORITHM_ECDSA_P256
	case crypto.ECDSAP384:
		return signerpb.Algorithm_ALGORITHM_ECDSA_P384
	case crypto.ECDSAP521:
		return signerpb.Algorithm_ALGORITHM_ECDSA_P521
	default:
		return signerpb.Algorithm_ALGORITHM_UNSPECIFIED
	}
}

// hashFromProto maps a protocol hash to a crypto hash and its expected digest
// length in bytes.
func hashFromProto(h signerpb.Hash) (crypto.Hash, int, error) {
	switch h {
	case signerpb.Hash_HASH_SHA256:
		return crypto.SHA256, 32, nil
	case signerpb.Hash_HASH_SHA384:
		return crypto.SHA384, 48, nil
	case signerpb.Hash_HASH_SHA512:
		return crypto.SHA512, 64, nil
	default:
		return "", 0, status.Errorf(codes.InvalidArgument, "unsupported hash %v", h)
	}
}

func paddingFromProto(p signerpb.RSAPadding) crypto.RSAPadding {
	if p == signerpb.RSAPadding_RSA_PADDING_PSS {
		return crypto.RSAPSS
	}
	return crypto.RSAPKCS1v15
}

func hashToProto(h crypto.Hash) signerpb.Hash {
	switch h {
	case crypto.SHA384:
		return signerpb.Hash_HASH_SHA384
	case crypto.SHA512:
		return signerpb.Hash_HASH_SHA512
	default: // crypto.SHA256 and the empty default
		return signerpb.Hash_HASH_SHA256
	}
}

func paddingToProto(p crypto.RSAPadding) signerpb.RSAPadding {
	if p == crypto.RSAPSS {
		return signerpb.RSAPadding_RSA_PADDING_PSS
	}
	return signerpb.RSAPadding_RSA_PADDING_PKCS1V15
}

func artifactSignRequestFromProto(req *signerpb.SignArtifactRequest) (ArtifactSignRequest, error) {
	if req == nil {
		return ArtifactSignRequest{}, status.Error(codes.InvalidArgument, "nil artifact sign request")
	}
	if req.GetKind() == "" {
		return ArtifactSignRequest{}, status.Error(codes.InvalidArgument, "missing artifact kind")
	}
	if req.GetTenantId() == "" {
		return ArtifactSignRequest{}, status.Error(codes.InvalidArgument, "missing tenant id")
	}
	if req.GetAuthorityId() == "" {
		return ArtifactSignRequest{}, status.Error(codes.InvalidArgument, "missing authority id")
	}
	if len(req.GetPayload()) == 0 {
		return ArtifactSignRequest{}, status.Error(codes.InvalidArgument, "missing artifact payload")
	}
	payload := append([]byte(nil), req.GetPayload()...)
	return ArtifactSignRequest{
		Kind:        req.GetKind(),
		TenantID:    req.GetTenantId(),
		AuthorityID: req.GetAuthorityId(),
		KeyID:       req.GetKeyId(),
		Payload:     payload,
	}, nil
}

func artifactSignatureToProto(res ArtifactSignature) (*signerpb.SignArtifactResponse, error) {
	if res.KeyID == "" {
		return nil, status.Error(codes.Internal, "artifact signer returned empty key id")
	}
	if len(res.PublicKeyDER) == 0 {
		return nil, status.Error(codes.Internal, "artifact signer returned empty public key")
	}
	if len(res.Signature) == 0 {
		return nil, status.Error(codes.Internal, "artifact signer returned empty signature")
	}
	alg := algorithmToProto(res.Algorithm)
	if alg == signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		return nil, status.Error(codes.Internal, "artifact signer returned unsupported algorithm")
	}
	return &signerpb.SignArtifactResponse{
		KeyId:     res.KeyID,
		Algorithm: alg,
		PublicKey: append([]byte(nil), res.PublicKeyDER...),
		Signature: append([]byte(nil), res.Signature...),
	}, nil
}

func artifactSignRequestToProto(req ArtifactSignRequest) *signerpb.SignArtifactRequest {
	return &signerpb.SignArtifactRequest{
		Kind:        req.Kind,
		TenantId:    req.TenantID,
		AuthorityId: req.AuthorityID,
		KeyId:       req.KeyID,
		Payload:     append([]byte(nil), req.Payload...),
	}
}

func artifactSignatureFromProto(resp *signerpb.SignArtifactResponse) (ArtifactSignature, error) {
	if resp == nil {
		return ArtifactSignature{}, status.Error(codes.InvalidArgument, "nil artifact sign response")
	}
	alg, err := algorithmFromProto(resp.GetAlgorithm())
	if err != nil {
		return ArtifactSignature{}, err
	}
	return ArtifactSignature{
		KeyID:        resp.GetKeyId(),
		Algorithm:    alg,
		PublicKeyDER: append([]byte(nil), resp.GetPublicKey()...),
		Signature:    append([]byte(nil), resp.GetSignature()...),
	}, nil
}

func operationRequestFromProto(req *signerpb.OperationRequest) (OperationRequest, error) {
	if req == nil {
		return OperationRequest{}, status.Error(codes.InvalidArgument, "nil operation request")
	}
	if req.GetTenantId() == "" {
		return OperationRequest{}, status.Error(codes.InvalidArgument, "missing tenant id")
	}
	if req.GetOperation() == "" {
		return OperationRequest{}, status.Error(codes.InvalidArgument, "missing operation")
	}
	if len(req.GetPreconditions()) == 0 {
		return OperationRequest{}, status.Error(codes.InvalidArgument, "missing operation preconditions")
	}
	return OperationRequest{
		TenantID:       req.GetTenantId(),
		Operation:      req.GetOperation(),
		SubjectRef:     req.GetSubjectRef(),
		IdempotencyKey: req.GetIdempotencyKey(),
		Preconditions:  append([]byte(nil), req.GetPreconditions()...),
		Evidence:       append([]byte(nil), req.GetEvidence()...),
		Context:        append([]byte(nil), req.GetContext()...),
	}, nil
}

func operationDecisionToProto(dec OperationDecision) *signerpb.OperationResponse {
	return &signerpb.OperationResponse{
		Approved:      dec.Approved,
		RefusalRecord: append([]byte(nil), dec.RefusalRecord...),
		Authorization: append([]byte(nil), dec.Authorization...),
		Evidence:      append([]byte(nil), dec.Evidence...),
	}
}

func operationRequestToProto(req OperationRequest) *signerpb.OperationRequest {
	return &signerpb.OperationRequest{
		TenantId:       req.TenantID,
		Operation:      req.Operation,
		SubjectRef:     req.SubjectRef,
		IdempotencyKey: req.IdempotencyKey,
		Preconditions:  append([]byte(nil), req.Preconditions...),
		Evidence:       append([]byte(nil), req.Evidence...),
		Context:        append([]byte(nil), req.Context...),
	}
}

func operationDecisionFromProto(resp *signerpb.OperationResponse) OperationDecision {
	if resp == nil {
		return OperationDecision{}
	}
	return OperationDecision{
		Approved:      resp.GetApproved(),
		RefusalRecord: append([]byte(nil), resp.GetRefusalRecord()...),
		Authorization: append([]byte(nil), resp.GetAuthorization()...),
		Evidence:      append([]byte(nil), resp.GetEvidence()...),
	}
}

// mintRequestFromProto decodes a wire MintSuccessorRequest into the in-signer
// MintRequest (INT-01). It never carries private key material — the predecessor is
// a handle only.
func mintRequestFromProto(req *signerpb.MintSuccessorRequest) (MintRequest, error) {
	if req == nil {
		return MintRequest{}, status.Error(codes.InvalidArgument, "nil mint request")
	}
	alg, err := algorithmFromProto(req.GetTargetAlgorithm())
	if err != nil {
		return MintRequest{}, err
	}
	return MintRequest{
		IdentityID:               req.GetIdentityId(),
		TenantID:                 req.GetTenantId(),
		DeploymentScope:          req.GetDeploymentScope(),
		PredecessorHandle:        req.GetPredecessorHandle(),
		AssertedPredecessorEpoch: req.GetAssertedPredecessorEpoch(),
		TargetAlgorithm:          alg,
		PolicyRef:                req.GetPolicyRef(),
		PolicyDecision:           req.GetPolicyDecision(),
		Authorization:            req.GetAuthorization(),
		BreakGlass:               req.GetBreakGlass(),
		Attestation:              req.GetAttestation(),
		DelegationScope:          req.GetDelegationScope(),
		NotBefore:                req.GetNotBefore(),
		NotAfter:                 req.GetNotAfter(),
	}, nil
}

// mintResultToProto encodes an in-signer MintResult for the wire (INT-01). Only
// public material crosses the boundary.
func mintResultToProto(res MintResult) *signerpb.MintSuccessorResponse {
	return &signerpb.MintSuccessorResponse{
		Epoch:              res.Epoch,
		SuccessorAlgorithm: algorithmToProto(res.SuccessorAlgorithm),
		SuccessorPublicKey: res.SuccessorPublicDER,
		EncodedRecord:      res.EncodedRecord,
	}
}

// mintRequestToProto encodes an in-signer MintRequest for the wire, used by the
// control-plane client (INT-01).
func mintRequestToProto(req MintRequest) *signerpb.MintSuccessorRequest {
	return &signerpb.MintSuccessorRequest{
		IdentityId:               req.IdentityID,
		TenantId:                 req.TenantID,
		DeploymentScope:          req.DeploymentScope,
		PredecessorHandle:        req.PredecessorHandle,
		AssertedPredecessorEpoch: req.AssertedPredecessorEpoch,
		TargetAlgorithm:          algorithmToProto(req.TargetAlgorithm),
		PolicyRef:                req.PolicyRef,
		PolicyDecision:           req.PolicyDecision,
		Authorization:            req.Authorization,
		BreakGlass:               req.BreakGlass,
		Attestation:              req.Attestation,
		DelegationScope:          req.DelegationScope,
		NotBefore:                req.NotBefore,
		NotAfter:                 req.NotAfter,
	}
}

// mintResultFromProto decodes a wire MintSuccessorResponse for the client (INT-01).
// The authoritative successor algorithm is also bound inside the encoded record, so
// an unknown enum here degrades to the empty algorithm rather than an error.
func mintResultFromProto(resp *signerpb.MintSuccessorResponse) MintResult {
	if resp == nil {
		return MintResult{}
	}
	alg, _ := algorithmFromProto(resp.GetSuccessorAlgorithm())
	return MintResult{
		Epoch:              resp.GetEpoch(),
		SuccessorAlgorithm: alg,
		SuccessorPublicDER: resp.GetSuccessorPublicKey(),
		EncodedRecord:      resp.GetEncodedRecord(),
	}
}

// validateSignRequest is the request-parser guard fuzzed by the protocol fuzz
// test. It must never panic on arbitrary input and must reject malformed
// requests with a structured error.
func validateSignRequest(req *signerpb.SignRequest) error {
	if req == nil || req.GetHandle() == nil || req.GetHandle().GetId() == "" {
		return status.Error(codes.InvalidArgument, "missing key handle")
	}
	if len(req.GetDigest()) == 0 {
		return status.Error(codes.InvalidArgument, "missing digest")
	}
	if len(req.GetDigest()) > maxDigestLen {
		return status.Errorf(codes.InvalidArgument, "digest too long: %d bytes", len(req.GetDigest()))
	}
	_, wantLen, err := hashFromProto(req.GetHash())
	if err != nil {
		return err
	}
	if len(req.GetDigest()) != wantLen {
		return status.Errorf(codes.InvalidArgument, "digest length %d does not match hash %v", len(req.GetDigest()), req.GetHash())
	}
	return nil
}

// gatedIssueRequestToProto encodes an in-signer IssuancePreconditions + the requested
// agent-key algorithm for the wire, used by the control-plane client (AGID-INT-WIRE). It
// carries NO private key material -- every body is opaque bytes. An empty algorithm maps to
// ALGORITHM_UNSPECIFIED (the signer's key op then picks its default).
func gatedIssueRequestToProto(req IssuancePreconditions, alg crypto.Algorithm) *signerpb.GatedIssueRequest {
	return &signerpb.GatedIssueRequest{
		TenantId:          req.TenantID,
		TrustAnchorRef:    req.TrustAnchorRef,
		NotBefore:         req.NotBefore,
		NotAfter:          req.NotAfter,
		Preconditions:     req.Preconditions,
		SubjectRepr:       req.SubjectRepr,
		Attestation:       req.Attestation,
		AttestationMethod: req.AttestationMethod,
		Algorithm:         algorithmToProto(alg),
	}
}

// issuanceDecisionFromProto decodes a wire GatedIssueResponse for the client
// (AGID-INT-WIRE). It carries only public material: the approval flag, the signed refusal
// on a refusal, and, on approval, the opaque binding material + the issued credential
// public DER + opaque encoded record. No private key is present to decode.
func issuanceDecisionFromProto(resp *signerpb.GatedIssueResponse) IssuanceDecision {
	if resp == nil {
		return IssuanceDecision{}
	}
	return IssuanceDecision{
		Approved:            resp.GetApproved(),
		RefusalRecord:       resp.GetRefusalRecord(),
		BindingMaterial:     resp.GetBindingMaterial(),
		CredentialPublicDER: resp.GetCredentialPublicDer(),
		EncodedRecord:       resp.GetEncodedRecord(),
	}
}
