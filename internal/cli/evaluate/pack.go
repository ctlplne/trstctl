// SPDX-License-Identifier: BUSL-1.1

package evaluate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// Kind is the artifact domain the pack is signed under; the isolated signer
// admits it and a verifier requires it.
const Kind = jose.ArtifactEvaluationPack

// ArtifactSigner signs evidence under an admitted artifact kind.
type ArtifactSigner interface {
	SignArtifact(kind string, payload []byte) (string, error)
}

// Sign signs the pack's exact JSON with its signature left out.
func Sign(p *Pack, signer ArtifactSigner, keyID string) error {
	if signer == nil {
		return errors.New("evaluate: no signer")
	}
	p.Signature = nil
	payload, err := json.Marshal(p)
	if err != nil {
		return err
	}
	compact, err := signer.SignArtifact(Kind, payload)
	if err != nil {
		return fmt.Errorf("evaluate: sign pack: %w", err)
	}
	p.Signature = &Signature{Alg: "RS256", KeyID: keyID, JWS: compact}
	return nil
}

// Verify checks a saved pack against a separately pinned audit JWK set: the
// signature and its artifact domain, and that the pack beside the signature
// is exactly the signed pack. The audit export inside it is checked against
// the same keys, never against the key set the pack carries.
func Verify(document []byte, keys *jose.JWKSet) (Pack, string, error) {
	if keys == nil {
		return Pack{}, "", errors.New("evaluate: a pinned audit JWK set is required")
	}
	var saved Pack
	if err := json.Unmarshal(document, &saved); err != nil {
		return Pack{}, "", fmt.Errorf("evaluate: decode pack: %w", err)
	}
	if saved.Signature == nil || saved.Signature.JWS == "" {
		return Pack{}, "", errors.New("evaluate: the pack is not signed")
	}
	payload, kid, err := keys.VerifyArtifactWithKeyID(saved.Signature.JWS, Kind)
	if err != nil {
		return Pack{}, "", fmt.Errorf("evaluate: signature: %w", err)
	}
	var signed Pack
	if err := json.Unmarshal(payload, &signed); err != nil {
		return Pack{}, "", fmt.Errorf("evaluate: decode signed pack: %w", err)
	}
	if signed.Format != PackFormat {
		return Pack{}, "", fmt.Errorf("evaluate: unsupported pack format %q", signed.Format)
	}
	// Compare meaning, not bytes: re-indenting the saved file changes nothing
	// signed, while any changed value differs.
	sig := saved.Signature
	saved.Signature = nil
	savedJSON, err := json.Marshal(saved)
	if err != nil {
		return Pack{}, "", err
	}
	signedJSON, err := json.Marshal(signed)
	if err != nil {
		return Pack{}, "", err
	}
	if !bytes.Equal(savedJSON, signedJSON) {
		return Pack{}, "", errors.New("evaluate: the pack differs from the signed pack")
	}
	signed.Signature = sig
	return signed, kid, nil
}

// VerifyAuditExport checks the audit export a pack carries against the pinned
// audit keys, never the key set the pack carries beside it.
func VerifyAuditExport(p Pack, keys *jose.JWKSet) error {
	if p.AuditExport == nil {
		return nil
	}
	result, err := auditanchor.VerifyArtifact(p.AuditExport.Export, auditanchor.VerificationOptions{
		Format: auditanchor.FormatJWS, AuditKeys: keys, AllowUnanchoredJWS: true,
	})
	if err != nil {
		return fmt.Errorf("evaluate: the pack's audit export: %w", err)
	}
	if !result.AuditSignatureVerified {
		return errors.New("evaluate: the pack's audit export carries no verified audit signature")
	}
	return nil
}
