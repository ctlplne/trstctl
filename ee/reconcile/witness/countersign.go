// SPDX-License-Identifier: LicenseRef-trstctl-EE

package witness

import (
	"context"
	"strings"
	"time"

	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// CounterSignRequest carries a witness for countersignature by the second
// authority, so the artifact is mutually attested rather than one-sided
// (XREC-claims-6, 21).
type CounterSignRequest struct {
	Evidence           Evidence
	Digests            []digest.SignedDigest
	AuthorityID        string
	KeyID              string
	TrustedDigestKeys  map[string]crypto.PublicKey
	TrustedWitnessKeys map[string]crypto.PublicKey
}

func CounterSign(ctx context.Context, client ArtifactSigningClient, req CounterSignRequest) (WitnessSignature, error) {
	authorityID := strings.TrimSpace(req.AuthorityID)
	if client == nil || authorityID == "" {
		return WitnessSignature{}, ErrInvalidWitness
	}
	if err := VerifyOffline(OfflineVerifyRequest{
		Evidence:           req.Evidence,
		Digests:            req.Digests,
		TrustedDigestKeys:  req.TrustedDigestKeys,
		TrustedWitnessKeys: req.TrustedWitnessKeys,
		VerifierAuthority:  authorityID,
	}); err != nil {
		return WitnessSignature{}, err
	}
	payload, err := req.Evidence.Body.CanonicalBytes()
	if err != nil {
		return WitnessSignature{}, err
	}
	hash := crypto.SHA256Sum(payload)
	res, err := client.SignArtifact(ctx, signing.ArtifactSignRequest{
		Kind:        digest.ArtifactKindDivergenceWitness,
		TenantID:    req.Evidence.Body.TenantID,
		AuthorityID: authorityID,
		KeyID:       strings.TrimSpace(req.KeyID),
		Payload:     payload,
	})
	if err != nil {
		return WitnessSignature{}, err
	}
	return WitnessSignature{
		WitnessID:    req.Evidence.Body.WitnessID,
		AuthorityID:  authorityID,
		ContentHash:  hash,
		KeyID:        res.KeyID,
		Algorithm:    res.Algorithm,
		PublicKeyDER: append([]byte(nil), res.PublicKeyDER...),
		Signature:    append([]byte(nil), res.Signature...),
		SignedAt:     time.Now().UTC().Unix(),
	}, nil
}
