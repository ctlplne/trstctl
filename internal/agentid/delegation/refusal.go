// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"bytes"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

// refusal.go carries the signer's SIGNED refusal artifact -- the fail-closed spine of
// INV-A1 (AGID-claims-1/14). On ANY failed pre-keygen check the gate signs, inside the AN-4
// boundary, an artifact naming the failed HOP and the failed CHECK, and returns it in
// IssuanceDecision.RefusalRecord with Approved=false and ZERO key ops. The caller
// appends an agent.refusal.recorded event carrying it. A refusal is as attributable as
// an issuance: every signer OUTCOME is evidenced, not just successes.
//
// The refusal is signed with a refusal-signing crypto.Signer the gate is constructed
// with (AN-3). No private key material and no raw prompt is ever placed in the
// artifact (AN-8): it carries the tenant, subject, the named failed check, the failed
// hop index, the request digest, and the signature.

const refusalDomain = "agid/agentid/refusal/v1"

// Failed-check identifiers a refusal cites. These name WHICH pre-keygen check failed,
// so the refusal is diagnostic without leaking evidence. They are stable strings the
// relying party and audit tooling match on.
const (
	CheckDecode        = "precondition_decode"   // opaque body failed to decode
	CheckChainLinkage  = "chain_linkage"         // parent-hash / root-anchor linkage broken
	CheckHopSignature  = "hop_signature"         // a hop's delegator signature did not verify
	CheckRootAnchor    = "root_anchor"           // chain did not chain to a held root anchor
	CheckExpiry        = "validity_expiry"       // a hop (or the request window) is expired/out of range
	CheckDepth         = "delegation_depth"      // depth accounting exceeded
	CheckRevocation    = "revocation"            // a hop is revoked (or the reader failed)
	CheckNarrowing     = "authority_narrowing"   // a hop widened authority vs its parent
	CheckAttestation   = "attestation"           // attestation evidence missing/invalid/below class
	CheckAgentStack    = "agent_stack"           // agent-stack representation invalid
	CheckBindingTarget = "binding_target_absent" // neither a chain nor an agent-stack repr to bind
	CheckReachability  = "reachability"          // reachability verdict absent/invalid/stale or a ceiling exceeded
)

// ErrRefusalArtifact is returned when a refusal artifact does not verify.
var ErrRefusalArtifact = errors.New("delegation: refusal artifact invalid")

// RefusalArtifact is the signer's signed evidence of a refused issuance (claims
// 1/14). It names the failed check and the failed hop, references the refused request
// by digest, and carries the signer's signature. HopIndex is the zero-based index of
// the failing hop in the root-first chain, or -1 when the failure is not hop-specific
// (a decode failure, a missing binding target, an attestation failure).
type RefusalArtifact struct {
	SignerID      string `json:"signer_id"`
	TenantID      string `json:"tenant_id"`
	SubjectID     string `json:"subject_id"`
	FailedCheck   string `json:"failed_check"`
	HopIndex      int    `json:"hop_index"`
	Detail        string `json:"detail,omitempty"` // non-secret human-readable detail (e.g. the class not met)
	RequestDigest []byte `json:"request_digest,omitempty"`
	IssuedAt      int64  `json:"issued_at"`
	Signature     []byte `json:"sig,omitempty"`
}

// refusalMessage is the stable, length-prefixed byte encoding the refusal signature
// covers (the Signature field is excluded).
func refusalMessage(a RefusalArtifact) []byte {
	var b bytes.Buffer
	b.WriteString(refusalDomain)
	writeStr(&b, a.SignerID)
	writeStr(&b, a.TenantID)
	writeStr(&b, a.SubjectID)
	writeStr(&b, a.FailedCheck)
	writeI64(&b, int64(a.HopIndex))
	writeStr(&b, a.Detail)
	writeBytes(&b, a.RequestDigest)
	writeI64(&b, a.IssuedAt)
	return b.Bytes()
}

// SignRefusal signs a refusal artifact with the signer's refusal-signing key (called
// inside the signer boundary). The Signature field of art is ignored on input.
func SignRefusal(refusalSigner crypto.Signer, art RefusalArtifact) (RefusalArtifact, error) {
	art.Signature = nil
	sig, err := refusalSigner.Sign(refusalMessage(art), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return RefusalArtifact{}, err
	}
	art.Signature = sig
	return art, nil
}

// VerifyRefusal verifies a refusal artifact against the signer's refusal-signing
// public key (PKIX DER). It fails closed: a missing or bad signature returns
// ErrRefusalArtifact.
func VerifyRefusal(signerPubDER []byte, art RefusalArtifact) error {
	unsigned := art
	unsigned.Signature = nil
	if len(art.Signature) == 0 || crypto.VerifyMessage(signerPubDER, refusalMessage(unsigned), art.Signature) != nil {
		return ErrRefusalArtifact
	}
	return nil
}

// EncodeRefusal serializes a refusal artifact for carriage in
// IssuanceDecision.RefusalRecord and the agent.refusal.recorded event.
func EncodeRefusal(art RefusalArtifact) ([]byte, error) { return json.Marshal(art) }

// DecodeRefusal deserializes a refusal artifact from the opaque RefusalRecord bytes.
func DecodeRefusal(b []byte) (RefusalArtifact, error) {
	var art RefusalArtifact
	if err := json.Unmarshal(b, &art); err != nil {
		return RefusalArtifact{}, ErrRefusalArtifact
	}
	return art, nil
}
