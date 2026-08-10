// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// The detached signature over invoice evidence (epic L2).
//
// The signature answers one question the digest cannot: WHO stands behind this
// document. A digest proves two readers hold the same bytes; the signature
// proves the deployment's audit-export key attested them — the same key that
// signs every other auditor-facing export, so a finance team verifies invoices
// and audit bundles against one public key, not a menagerie.

// EvidenceSignature is the detached JWS over the document's canonical bytes.
// Same shape as the doctor receipt's signature, deliberately: a verifier who
// can check one can check the other.
type EvidenceSignature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	JWS   string `json:"jws"`
}

// EvidenceSigner signs canonical evidence bytes. The route holds one when the
// deployment's audit-export key is attached.
type EvidenceSigner interface {
	SignEvidence(canonical []byte) (*EvidenceSignature, error)
}

// AuditKeySigner signs with the deployment's audit-export key.
type AuditKeySigner struct {
	Key *jose.SigningKey
}

// SignEvidence produces the detached JWS. The payload is the document's
// canonical rendering — exactly the bytes the digest hashes — so signature and
// digest attest the same thing and a verifier reconstructs one input, not two.
func (s *AuditKeySigner) SignEvidence(canonical []byte) (*EvidenceSignature, error) {
	if s == nil || s.Key == nil {
		return nil, fmt.Errorf("billing: no audit signing key attached")
	}
	jws, err := s.Key.SignArtifact(jose.ArtifactBillingInvoice, canonical)
	if err != nil {
		return nil, fmt.Errorf("billing: sign evidence: %w", err)
	}
	return &EvidenceSignature{Alg: "RS256", KeyID: s.Key.KeyID(), JWS: jws}, nil
}
