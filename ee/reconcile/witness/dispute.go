// SPDX-License-Identifier: LicenseRef-trstctl-EE

package witness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

type DisputeRequest struct {
	Evidence    Evidence
	AuthorityID string
	KeyID       string
	DigestHash  []byte
	Reason      string
	DisputedAt  int64
}

type DisputeRecord struct {
	WitnessID    string           `json:"witness_id"`
	AuthorityID  string           `json:"authority_id"`
	DigestHash   []byte           `json:"digest_hash"`
	Reason       string           `json:"reason"`
	ContentHash  []byte           `json:"content_hash"`
	KeyID        string           `json:"key_id"`
	Algorithm    crypto.Algorithm `json:"algorithm"`
	PublicKeyDER []byte           `json:"public_key_der"`
	Signature    []byte           `json:"signature"`
	DisputedAt   int64            `json:"disputed_at"`
}

func Dispute(ctx context.Context, client ArtifactSigningClient, req DisputeRequest) (DisputeRecord, error) {
	authorityID := strings.TrimSpace(req.AuthorityID)
	reason := strings.TrimSpace(req.Reason)
	if client == nil || authorityID == "" || reason == "" || len(req.DigestHash) == 0 || req.DisputedAt == 0 {
		return DisputeRecord{}, ErrInvalidWitness
	}
	body := disputeBody{
		WitnessID:   req.Evidence.Body.WitnessID,
		AuthorityID: authorityID,
		DigestHash:  append([]byte(nil), req.DigestHash...),
		Reason:      reason,
		DisputedAt:  req.DisputedAt,
	}
	payload, err := body.canonicalBytes()
	if err != nil {
		return DisputeRecord{}, err
	}
	hash := crypto.SHA256Sum(payload)
	res, err := client.SignArtifact(ctx, signing.ArtifactSignRequest{
		Kind:        digest.ArtifactKindWitnessDispute,
		TenantID:    req.Evidence.Body.TenantID,
		AuthorityID: authorityID,
		KeyID:       strings.TrimSpace(req.KeyID),
		Payload:     payload,
	})
	if err != nil {
		return DisputeRecord{}, err
	}
	return DisputeRecord{
		WitnessID:    body.WitnessID,
		AuthorityID:  body.AuthorityID,
		DigestHash:   body.DigestHash,
		Reason:       body.Reason,
		ContentHash:  hash,
		KeyID:        res.KeyID,
		Algorithm:    res.Algorithm,
		PublicKeyDER: append([]byte(nil), res.PublicKeyDER...),
		Signature:    append([]byte(nil), res.Signature...),
		DisputedAt:   body.DisputedAt,
	}, nil
}

func (d DisputeRecord) Verify(trusted map[string]crypto.PublicKey) error {
	if d.WitnessID == "" || d.AuthorityID == "" || len(d.DigestHash) == 0 || d.Reason == "" || d.DisputedAt == 0 {
		return ErrInvalidWitness
	}
	body := disputeBody{
		WitnessID:   d.WitnessID,
		AuthorityID: d.AuthorityID,
		DigestHash:  append([]byte(nil), d.DigestHash...),
		Reason:      d.Reason,
		DisputedAt:  d.DisputedAt,
	}
	payload, err := body.canonicalBytes()
	if err != nil {
		return err
	}
	if d.KeyID == "" || len(d.Signature) == 0 || len(d.PublicKeyDER) == 0 {
		return ErrInvalidWitness
	}
	hash := crypto.SHA256Sum(payload)
	if !bytes.Equal(hash, d.ContentHash) {
		return fmt.Errorf("%w: dispute content hash mismatch", ErrInvalidWitness)
	}
	pub, ok := trusted[d.KeyID]
	if !ok {
		return fmt.Errorf("%w: untrusted dispute key %s", ErrInvalidWitness, d.KeyID)
	}
	if pub.Algorithm != d.Algorithm || !bytes.Equal(pub.DER, d.PublicKeyDER) {
		return fmt.Errorf("%w: dispute public key mismatch", ErrInvalidWitness)
	}
	if err := crypto.VerifyDigest(pub, hash, d.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("%w: dispute signature: %v", ErrInvalidWitness, err)
	}
	return nil
}

type disputeBody struct {
	WitnessID   string `json:"witness_id"`
	AuthorityID string `json:"authority_id"`
	DigestHash  []byte `json:"digest_hash"`
	Reason      string `json:"reason"`
	DisputedAt  int64  `json:"disputed_at"`
}

func (b disputeBody) canonicalBytes() ([]byte, error) {
	if b.WitnessID == "" || b.AuthorityID == "" || len(b.DigestHash) == 0 || b.Reason == "" || b.DisputedAt == 0 {
		return nil, ErrInvalidWitness
	}
	return json.Marshal(b)
}
