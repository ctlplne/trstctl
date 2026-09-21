// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// issuance_keyop.go completes the AGID-INT-WIRE core seam: the after-approval issuance
// key op and the GatedIssue gRPC handler that drives a gated agent-credential issuance
// INSIDE the signer over the transport (mirroring MintSuccessor for the PCAS mint).
//
// The split is the same one AGID-04a fixed for the gate: the CORE names only a generic
// seam and forwards opaque bodies; the EDITION supplies the concrete key op (agent
// keygen + certify-under-CA + binding) without core importing ee/. The core guarantee is
// INV-A1: gatedIssue consults the attached IssuanceGate BEFORE any key op, and the key op
// runs ONLY on an approving decision. GatedIssue wires decode -> gatedIssue(keyOp) ->
// encode and returns ONLY public material (the credential public key + the opaque encoded
// record); no private key ever crosses the boundary.

// IssuanceKeyOp is the generic after-approval issuance key op attached to the AN-4 signer
// (WithIssuanceKeyOp). It is invoked by GatedIssue ONLY after the attached IssuanceGate
// returns an APPROVING decision (INV-A1). It performs the real key operation inside the
// boundary -- generating the agent credential key here and certifying it under the
// signer-held issuing CA -- and returns only public material. The core defines only this
// seam; the concrete certify/binding semantics (which OID, which CA, how the binding is
// stamped) live in an edition implementation and are opaque to core.
//
// It carries NO private key material across the seam: the returned IssuedCredential holds
// only the credential's public DER and the opaque encoded record. The agent private key
// stays in the signer's custody (SignerCustody), generated via the injected custody.
type IssuanceKeyOp interface {
	// MintApprovedCredential mints the agent credential for an APPROVED issuance. req is
	// the original opaque request (so the key op can derive a subject/CN); decision is the
	// gate's approving decision (carrying the opaque BindingMaterial to bind); alg is the
	// requested agent-key algorithm (ALGORITHM_UNSPECIFIED-equivalent empty means the key
	// op picks its default). It returns only public material.
	MintApprovedCredential(ctx context.Context, req IssuancePreconditions, decision IssuanceDecision, alg crypto.Algorithm) (IssuedCredential, error)
}

// IssuedCredential is the public-only result of an after-approval issuance key op. It
// carries NO private key material: the agent private key stays in the signer's custody.
type IssuedCredential struct {
	// CredentialPublicDER is the PKIX/DER SubjectPublicKeyInfo of the issued agent
	// credential's public key. Public material only.
	CredentialPublicDER []byte
	// EncodedRecord is the opaque encoded issuance record the key op produced (for example
	// the issued certificate DER carrying the binding extension). Opaque to core.
	EncodedRecord []byte
}

// custodyAwareIssuanceKeyOp is implemented by an issuance key op that wants the signer's
// own key custody injected, so it can generate the agent key INSIDE the signer (the
// private key never leaves). Core defines only this seam; the edition key op opts in. It
// mirrors custodyAwareMinter precisely.
type custodyAwareIssuanceKeyOp interface {
	UseSignerCustody(SignerCustody)
}

// ErrNoIssuanceKeyOp is returned by the GatedIssue path when no issuance key op is
// attached (core-only build, or an unlicensed signer). It fails closed with this, mirroring
// ErrNoMinter for the succession path.
var ErrNoIssuanceKeyOp = errors.New("signing: no issuance key op attached")

// WithIssuanceKeyOp attaches the after-approval issuance key op to the signer, beside
// WithIssuanceGate/WithSuccessionMinter/WithKeyFactory. The core names only the generic
// seam; the edition supplies the implementation without importing ee/ into core. A key op
// that opts into custodyAwareIssuanceKeyOp has the signer's key custody injected at
// construction (bindIssuanceKeyOpCustody).
func WithIssuanceKeyOp(op IssuanceKeyOp) ServerOption {
	return func(s *Server) {
		if op != nil {
			s.issuanceKeyOp = op
		}
	}
}

// bindIssuanceKeyOpCustody injects this signer's key custody into the attached issuance
// key op, if it opts into the seam. Called once at construction (bindMinterCustody's
// sibling), before serving, so no lock is required.
func (s *Server) bindIssuanceKeyOpCustody() {
	if s.issuanceKeyOp == nil {
		return
	}
	if ca, ok := s.issuanceKeyOp.(custodyAwareIssuanceKeyOp); ok {
		ca.UseSignerCustody(s)
	}
}

// GatedIssue is the gRPC handler that satisfies signerpb.SignerServiceServer for the
// AGID chain-bound issuance path (AGID-INT-WIRE). It decodes the wire request into the
// generic IssuancePreconditions, drives gatedIssue -- which consults the attached
// IssuanceGate BEFORE any key op (INV-A1) and, on approval, runs the attached issuance
// key op INSIDE the signer to generate + certify the agent credential -- and returns ONLY
// public material: the approval flag, the opaque signed refusal on a refusal, and, on an
// approval, the opaque binding material + the issued credential public key + the opaque
// encoded record.
//
// Fail-closed behavior mirrors MintSuccessor:
//   - no IssuanceGate attached  => ErrNoIssuanceGate  => UNIMPLEMENTED (core-only build).
//   - gate refuses              => Approved:false + signed RefusalRecord, ZERO key ops.
//   - approved but no key op     => ErrNoIssuanceKeyOp => UNIMPLEMENTED (cannot mint).
//   - key op error              => Internal.
//
// No private key crosses the boundary: the agent private key is generated in and stays in
// the signer's custody; only its certified public form and the opaque record return. The
// control plane can request an issuance over this RPC but cannot forge one.
func (s *Server) GatedIssue(ctx context.Context, req *signerpb.GatedIssueRequest) (*signerpb.GatedIssueResponse, error) {
	pre, alg, err := issuancePreconditionsFromProto(req)
	if err != nil {
		return nil, err
	}

	// The key op closure is the INV-A1 after-approval arm: gatedIssue calls it only once
	// the gate has approved. It performs the real key op inside the boundary via the
	// attached issuance key op and captures the public credential material it produced.
	var issued IssuedCredential
	keyOp := func(ctx context.Context, decision IssuanceDecision) error {
		s.mu.Lock()
		op := s.issuanceKeyOp
		s.mu.Unlock()
		if op == nil {
			// Fail closed: the gate approved but no key op is attached to mint. Surface a
			// sentinel the handler maps to UNIMPLEMENTED (mirrors the no-minter stance).
			return ErrNoIssuanceKeyOp
		}
		out, err := op.MintApprovedCredential(ctx, pre, decision, alg)
		if err != nil {
			return err
		}
		issued = out
		return nil
	}

	decision, err := s.gatedIssue(ctx, pre, keyOp)
	if err != nil {
		switch {
		case errors.Is(err, ErrNoIssuanceGate):
			return nil, status.Error(codes.Unimplemented, err.Error())
		case errors.Is(err, ErrNoIssuanceKeyOp):
			return nil, status.Error(codes.Unimplemented, err.Error())
		default:
			return nil, status.Errorf(codes.Internal, "gated issue: %v", err)
		}
	}

	return gatedIssueResponseToProto(decision, issued), nil
}

// issuancePreconditionsFromProto decodes a wire GatedIssueRequest into the in-signer
// generic IssuancePreconditions plus the requested agent-key algorithm. It carries NO
// private key material -- every body is opaque bytes the gate re-verifies. The algorithm
// degrades to the empty crypto.Algorithm on ALGORITHM_UNSPECIFIED (the key op then picks
// its default), so an omitted algorithm is not an error.
func issuancePreconditionsFromProto(req *signerpb.GatedIssueRequest) (IssuancePreconditions, crypto.Algorithm, error) {
	if req == nil {
		return IssuancePreconditions{}, "", status.Error(codes.InvalidArgument, "nil gated issue request")
	}
	var alg crypto.Algorithm
	if req.GetAlgorithm() != signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		a, err := algorithmFromProto(req.GetAlgorithm())
		if err != nil {
			return IssuancePreconditions{}, "", err
		}
		alg = a
	}
	pre := IssuancePreconditions{
		TenantID:          req.GetTenantId(),
		TrustAnchorRef:    req.GetTrustAnchorRef(),
		NotBefore:         req.GetNotBefore(),
		NotAfter:          req.GetNotAfter(),
		Preconditions:     req.GetPreconditions(),
		SubjectRepr:       req.GetSubjectRepr(),
		Attestation:       req.GetAttestation(),
		AttestationMethod: req.GetAttestationMethod(),
	}
	return pre, alg, nil
}

// gatedIssueResponseToProto encodes an in-signer IssuanceDecision + the issued public
// material for the wire. ONLY public material crosses: on a refusal, the signed refusal
// record; on an approval, the opaque binding material and the issued credential's public
// DER + opaque encoded record. No private key is ever placed in the response.
func gatedIssueResponseToProto(decision IssuanceDecision, issued IssuedCredential) *signerpb.GatedIssueResponse {
	resp := &signerpb.GatedIssueResponse{
		Approved:      decision.Approved,
		RefusalRecord: decision.RefusalRecord,
	}
	if decision.Approved {
		resp.BindingMaterial = decision.BindingMaterial
		// Prefer the credential material the key op produced; fall back to any the gate
		// itself carried (an edition may mint inside the gate). Public material only.
		resp.CredentialPublicDer = firstNonEmpty(issued.CredentialPublicDER, decision.CredentialPublicDER)
		resp.EncodedRecord = firstNonEmpty(issued.EncodedRecord, decision.EncodedRecord)
	}
	return resp
}

// firstNonEmpty returns the first non-empty byte slice, or nil.
func firstNonEmpty(a, b []byte) []byte {
	if len(a) > 0 {
		return a
	}
	return b
}

// GenerateIssuanceKey generates an agent-credential key of alg INSIDE the signer under
// the given handle and returns a message-Signer view of it. It is the issuance-custody
// analog of GenerateSuccessorKey: the private key persists in the signer (sealed at rest
// when a key store is configured) so the issued agent can later use it, and it never leaves
// the boundary. The attached issuance key op calls it (via SignerCustody) to obtain the
// agent key it certifies. An empty handle is rejected fail-closed.
func (s *Server) GenerateIssuanceKey(handle string, alg crypto.Algorithm) (crypto.Signer, error) {
	if handle == "" {
		return nil, fmt.Errorf("signing: issuance key handle required")
	}
	return s.GenerateSuccessorKey(handle, alg)
}
