// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/agentid/reach"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const revocationProofDomain = "agid/non-revocation/issuance/v1"
const revocationProofLifetime = 5 * time.Second

// RevocationProof is a one-use control-plane statement that every subject and
// signed hop in one exact issuance request was clear at the read-model check.
// It carries no secret; the signer verifies it with its held public verdict key.
type RevocationProof struct {
	TenantID      string              `json:"tenant_id"`
	RequestDigest []byte              `json:"request_digest"`
	IssuedAt      int64               `json:"issued_at_unix_nano"`
	ExpiresAt     int64               `json:"expires_at_unix_nano"`
	Nonce         []byte              `json:"nonce"`
	Key           reach.VerdictKeyRef `json:"key"`
	Signature     []byte              `json:"signature"`
}

// ProofConsumer atomically spends a nonce before the signer performs a key op.
// Production persists it across signer restarts; a replay cannot mint twice.
type ProofConsumer interface {
	ConsumeProofNonce(tenantID string, nonce []byte, expiresAt int64) error
}

func (p RevocationProof) signingBytes() []byte {
	b, _ := json.Marshal(struct {
		Domain        string              `json:"domain"`
		TenantID      string              `json:"tenant_id"`
		RequestDigest []byte              `json:"request_digest"`
		IssuedAt      int64               `json:"issued_at_unix_nano"`
		ExpiresAt     int64               `json:"expires_at_unix_nano"`
		Nonce         []byte              `json:"nonce"`
		Key           reach.VerdictKeyRef `json:"key"`
	}{revocationProofDomain, p.TenantID, p.RequestDigest, p.IssuedAt, p.ExpiresAt, p.Nonce, p.Key})
	return b
}

// IssuanceRequestDigest binds the authorization to every input that can affect
// the minted credential. The proof field itself is cleared to avoid recursion.
func IssuanceRequestDigest(req signing.IssuancePreconditions) ([]byte, error) {
	body, err := decodePreconditions(req.Preconditions)
	if err != nil {
		return nil, err
	}
	body.RevocationProof = nil
	preconditions, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(struct {
		Domain            string           `json:"domain"`
		TenantID          string           `json:"tenant_id"`
		TrustAnchorRef    string           `json:"trust_anchor_ref"`
		NotBefore         int64            `json:"not_before"`
		NotAfter          int64            `json:"not_after"`
		Algorithm         crypto.Algorithm `json:"algorithm"`
		Preconditions     []byte           `json:"preconditions"`
		SubjectRepr       []byte           `json:"subject_repr"`
		Attestation       []byte           `json:"attestation"`
		AttestationMethod string           `json:"attestation_method"`
	}{revocationProofDomain, req.TenantID, req.TrustAnchorRef, req.NotBefore, req.NotAfter, req.Algorithm,
		preconditions, req.SubjectRepr, req.Attestation, req.AttestationMethod})
	if err != nil {
		return nil, err
	}
	return crypto.SHA256Sum(b), nil
}

// SignRevocationProof runs only after a fresh control-plane projection read. The
// nonce comes from internal/crypto and is generated for this one request.
func SignRevocationProof(req signing.IssuancePreconditions, key reach.VerdictKeyRef, signer crypto.Signer, nonce []byte, now time.Time) ([]byte, error) {
	if signer == nil || key.ID == "" || key.Algorithm != string(signer.Algorithm()) || len(nonce) != 32 {
		return nil, errors.New("delegation: invalid non-revocation proof signer or nonce")
	}
	digest, err := IssuanceRequestDigest(req)
	if err != nil {
		return nil, err
	}
	p := RevocationProof{
		TenantID: req.TenantID, RequestDigest: digest,
		IssuedAt: now.UnixNano(), ExpiresAt: now.Add(revocationProofLifetime).UnixNano(),
		Nonce: bytes.Clone(nonce), Key: key,
	}
	p.Signature, err = signer.Sign(p.signingBytes(), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// VerifyRevocationProof refuses absent, altered, stale, cross-tenant, or replayed
// authorization. A read-model outage cannot be bypassed with a blank proof.
func VerifyRevocationProof(req signing.IssuancePreconditions, encoded []byte, trust reach.VerdictTrustLookup, consumer ProofConsumer, now time.Time) error {
	if trust == nil || consumer == nil || len(encoded) == 0 {
		return errors.New("delegation: non-revocation authorization is unavailable")
	}
	var p RevocationProof
	if err := json.Unmarshal(encoded, &p); err != nil {
		return fmt.Errorf("delegation: decode non-revocation authorization: %w", err)
	}
	if p.TenantID != req.TenantID || len(p.Nonce) != 32 || len(p.RequestDigest) != 32 ||
		p.Key.ID == "" || p.IssuedAt <= 0 || p.ExpiresAt <= p.IssuedAt ||
		p.ExpiresAt-p.IssuedAt > int64(revocationProofLifetime) ||
		now.UnixNano() < p.IssuedAt || now.UnixNano() >= p.ExpiresAt {
		return errors.New("delegation: non-revocation authorization is stale or malformed")
	}
	digest, err := IssuanceRequestDigest(req)
	if err != nil || !bytes.Equal(digest, p.RequestDigest) {
		return errors.New("delegation: non-revocation authorization binds another request")
	}
	publicDER, ok := trust(p.Key.ID)
	if !ok || len(publicDER) == 0 || len(p.Signature) == 0 ||
		crypto.VerifyMessage(publicDER, p.signingBytes(), p.Signature) != nil {
		return errors.New("delegation: non-revocation authorization signature is invalid")
	}
	if err := consumer.ConsumeProofNonce(p.TenantID, p.Nonce, p.ExpiresAt); err != nil {
		return fmt.Errorf("delegation: non-revocation authorization replay or custody error: %w", err)
	}
	return nil
}
