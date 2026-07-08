// SPDX-License-Identifier: LicenseRef-trstctl-EE

package witness

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const defaultWitnessAuthority = "xrec-witness"

type ArtifactSigningClient interface {
	SignArtifact(context.Context, signing.ArtifactSignRequest) (signing.ArtifactSignature, error)
}

func Sign(ctx context.Context, client ArtifactSigningClient, body Body, keyID string) (SignedWitness, error) {
	return SignForAuthority(ctx, client, body, defaultWitnessAuthority, keyID)
}

func SignForAuthority(ctx context.Context, client ArtifactSigningClient, body Body, authorityID, keyID string) (SignedWitness, error) {
	if client == nil {
		return SignedWitness{}, ErrInvalidWitness
	}
	authorityID = strings.TrimSpace(authorityID)
	if authorityID == "" {
		return SignedWitness{}, ErrInvalidWitness
	}
	payload, err := body.CanonicalBytes()
	if err != nil {
		return SignedWitness{}, err
	}
	hash := crypto.SHA256Sum(payload)
	res, err := client.SignArtifact(ctx, signing.ArtifactSignRequest{
		Kind:        digest.ArtifactKindDivergenceWitness,
		TenantID:    body.TenantID,
		AuthorityID: authorityID,
		KeyID:       strings.TrimSpace(keyID),
		Payload:     payload,
	})
	if err != nil {
		return SignedWitness{}, err
	}
	return SignedWitness{
		Body:         body,
		WitnessHash:  hash,
		AuthorityID:  authorityID,
		KeyID:        res.KeyID,
		Algorithm:    res.Algorithm,
		PublicKeyDER: append([]byte(nil), res.PublicKeyDER...),
		Signature:    append([]byte(nil), res.Signature...),
		SignedAt:     time.Now().UTC(),
	}, nil
}

func (s SignedWitness) SignatureRecord() WitnessSignature {
	return WitnessSignature{
		WitnessID:    s.Body.WitnessID,
		AuthorityID:  s.AuthorityID,
		ContentHash:  append([]byte(nil), s.WitnessHash...),
		KeyID:        s.KeyID,
		Algorithm:    s.Algorithm,
		PublicKeyDER: append([]byte(nil), s.PublicKeyDER...),
		Signature:    append([]byte(nil), s.Signature...),
		SignedAt:     s.SignedAt.Unix(),
	}
}

func (s SignedWitness) Verify(trusted map[string]crypto.PublicKey) error {
	return s.SignatureRecord().VerifyForBody(s.Body, trusted)
}

type WitnessSignature struct {
	WitnessID    string           `json:"witness_id"`
	AuthorityID  string           `json:"authority_id"`
	ContentHash  []byte           `json:"content_hash"`
	KeyID        string           `json:"key_id"`
	Algorithm    crypto.Algorithm `json:"algorithm"`
	PublicKeyDER []byte           `json:"public_key_der"`
	Signature    []byte           `json:"signature"`
	SignedAt     int64            `json:"signed_at"`
}

func (s WitnessSignature) VerifyForBody(body Body, trusted map[string]crypto.PublicKey) error {
	if !body.VerifyWitnessID() || s.WitnessID != body.WitnessID || strings.TrimSpace(s.AuthorityID) == "" {
		return ErrInvalidWitness
	}
	payload, err := body.CanonicalBytes()
	if err != nil {
		return err
	}
	return s.VerifyPayload(payload, trusted)
}

func (s WitnessSignature) VerifyPayload(payload []byte, trusted map[string]crypto.PublicKey) error {
	if s.KeyID == "" || len(s.Signature) == 0 || len(s.PublicKeyDER) == 0 {
		return ErrInvalidWitness
	}
	hash := crypto.SHA256Sum(payload)
	if !bytes.Equal(hash, s.ContentHash) {
		return fmt.Errorf("%w: signature content hash mismatch", ErrInvalidWitness)
	}
	pub, ok := trusted[s.KeyID]
	if !ok {
		return fmt.Errorf("%w: untrusted witness key %s", ErrInvalidWitness, s.KeyID)
	}
	if pub.Algorithm != s.Algorithm || !bytes.Equal(pub.DER, s.PublicKeyDER) {
		return fmt.Errorf("%w: witness public key mismatch", ErrInvalidWitness)
	}
	if err := crypto.VerifyDigest(pub, hash, s.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("%w: witness signature: %v", ErrInvalidWitness, err)
	}
	return nil
}
