// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"bytes"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// evidenceDomain is the domain-separation tag prefixed to the canonical evidence
// bytes before signing, so a completion-evidence signature can never be confused with
// a signature over any other artifact (a delegation record, a refusal, a task
// envelope). It is versioned so the evidence shape can evolve without ambiguity.
const evidenceDomain = "agid/agentid/revocation-completion-evidence/v1"

// CompletionEvidence is the per-job completion proof recorded in the ledger when a
// revocation job's effect is performed (§7.3, AGID-claim-16 / INV-A9). It names the job
// (its idempotency key and directive), the target credential, the effect class that
// was performed, the completion timestamp, and the executor identity — exactly the
// fields the card enumerates. It is SIGNED (Signature over the canonical body via
// internal/crypto, AN-3) so AGID-11's terminal state rests on unforgeable per-job
// proof. PublicKey is the signer key's PKIX/DER hint; a relying party must
// compare it with an independently retained pin before verifying offline.
type CompletionEvidence struct {
	TenantID       string      `json:"tenant_id"`
	DirectiveID    string      `json:"directive_id"`
	IdempotencyKey string      `json:"idempotency_key"`
	CredentialID   string      `json:"credential_id"`
	EffectClass    EffectClass `json:"effect_class"`
	CompletedAt    int64       `json:"completed_at"`
	Executor       string      `json:"executor"`
	// Signature is the executor-signer's signature over the canonical evidence body
	// (evidenceBody). It is omitted from the body that is signed (a signature cannot
	// cover itself) and attached after.
	Signature []byte `json:"signature,omitempty"`
	// PublicKey is the PKIX/DER SubjectPublicKeyInfo of the verifying key.
	PublicKey []byte `json:"public_key,omitempty"`
}

// evidenceBodyBytes returns the canonical, deterministic bytes that are signed: the
// domain tag followed by the JSON of the evidence with Signature and PublicKey
// cleared (they cannot cover themselves). Marshaling a struct with sorted, fixed
// field order is deterministic, so the same evidence yields the same bytes on replay
// and on independent verification.
func (e CompletionEvidence) evidenceBodyBytes() ([]byte, error) {
	body := e
	body.Signature = nil
	body.PublicKey = nil
	j, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("revoke: marshal evidence body: %w", err)
	}
	var out []byte
	out = append(out, evidenceDomain...)
	out = append(out, ':')
	out = append(out, j...)
	return out, nil
}

// signCompletionEvidence signs the evidence body with signer and returns the evidence
// with Signature + PublicKey attached, plus the canonical body bytes that were signed
// (so the caller stores body + signature + public key together for offline
// verification). Signing goes through internal/crypto (AN-3); this package never
// touches a private key directly. A nil signer is a programming error (the cascade
// always supplies one).
func signCompletionEvidence(signer crypto.Signer, e CompletionEvidence) (CompletionEvidence, []byte, error) {
	if signer == nil {
		return CompletionEvidence{}, nil, fmt.Errorf("revoke: completion evidence requires a signer (AN-3)")
	}
	body, err := e.evidenceBodyBytes()
	if err != nil {
		return CompletionEvidence{}, nil, err
	}
	sig, err := signer.Sign(body, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return CompletionEvidence{}, nil, fmt.Errorf("revoke: sign completion evidence: %w", err)
	}
	pub := signer.Public()
	e.Signature = sig
	e.PublicKey = pub.DER
	return e, body, nil
}

// VerifyCompletionEvidence checks the signature against an independently pinned
// public key. The embedded key is only a key identifier; it cannot authorize itself.
func VerifyCompletionEvidence(e CompletionEvidence, pinnedPublicKey []byte) error {
	if len(e.Signature) == 0 {
		return fmt.Errorf("revoke: completion evidence has no signature")
	}
	if len(pinnedPublicKey) == 0 || !bytes.Equal(e.PublicKey, pinnedPublicKey) {
		return fmt.Errorf("revoke: completion evidence key does not match the pinned key")
	}
	body, err := e.evidenceBodyBytes()
	if err != nil {
		return err
	}
	pub := crypto.PublicKey{DER: pinnedPublicKey}
	if err := crypto.Verify(pub, body, e.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("revoke: completion evidence signature invalid: %w", err)
	}
	return nil
}

// decodeCompletionEvidence parses stored evidence-body bytes (without signature) plus
// the detached signature + public key back into a CompletionEvidence. The body bytes
// stored in the ledger are the domain-tagged canonical form produced by
// evidenceBodyBytes; this strips the domain tag and unmarshals, then reattaches the
// signature/public key so VerifyCompletionEvidence can check them against a pin.
func decodeCompletionEvidence(body, sig, pub []byte) (CompletionEvidence, error) {
	prefix := evidenceDomain + ":"
	if len(body) < len(prefix) || string(body[:len(prefix)]) != prefix {
		return CompletionEvidence{}, fmt.Errorf("revoke: evidence body missing domain tag")
	}
	var e CompletionEvidence
	if err := json.Unmarshal(body[len(prefix):], &e); err != nil {
		return CompletionEvidence{}, fmt.Errorf("revoke: decode evidence body: %w", err)
	}
	e.Signature = sig
	e.PublicKey = pub
	return e, nil
}
