// SPDX-License-Identifier: BUSL-1.1

package witness

import (
	"bytes"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/reconcile/digest"
)

type OfflineVerifyRequest struct {
	Evidence               Evidence
	Digests                []digest.SignedDigest
	TrustedDigestKeys      map[string]crypto.PublicKey
	TrustedWitnessKeys     map[string]crypto.PublicKey
	VerifierAuthority      string
	RequireCountersignFrom string
}

func VerifyOffline(req OfflineVerifyRequest) error {
	if err := req.Evidence.validateShape(); err != nil {
		return err
	}
	bodyPayload, err := req.Evidence.Body.CanonicalBytes()
	if err != nil {
		return err
	}
	digests, err := verifyDigestRefs(req.Evidence.Body, req.Digests, req.TrustedDigestKeys)
	if err != nil {
		return err
	}
	if req.VerifierAuthority != "" {
		if _, ok := digests[req.VerifierAuthority]; !ok {
			return fmt.Errorf("%w: verifier authority missing digest", ErrInvalidWitness)
		}
	}
	if err := verifyWitnessSignatures(bodyPayload, req.Evidence.Signatures, req.TrustedWitnessKeys); err != nil {
		return err
	}
	if err := verifyWitnessSignatures(bodyPayload, req.Evidence.CounterSignatures, req.TrustedWitnessKeys); err != nil {
		return err
	}
	if req.RequireCountersignFrom != "" && !hasSignatureFrom(req.Evidence.CounterSignatures, req.RequireCountersignFrom) {
		return fmt.Errorf("%w: missing required countersignature", ErrInvalidWitness)
	}
	for _, dispute := range req.Evidence.Disputes {
		if err := dispute.Verify(req.TrustedWitnessKeys); err != nil {
			return err
		}
	}
	for _, entry := range req.Evidence.Body.Entries {
		if err := verifyEntry(entry, digests); err != nil {
			return err
		}
	}
	return nil
}

func verifyDigestRefs(body Body, signed []digest.SignedDigest, trusted map[string]crypto.PublicKey) (map[string]digest.SignedDigest, error) {
	byAuthority := map[string]digest.SignedDigest{}
	for _, sd := range signed {
		if err := sd.Verify(trusted); err != nil {
			return nil, err
		}
		byAuthority[sd.Body.AuthorityID] = sd
	}
	for _, ref := range body.DigestRefs {
		sd, ok := byAuthority[ref.AuthorityID]
		if !ok {
			return nil, fmt.Errorf("%w: missing signed digest for %s", ErrInvalidWitness, ref.AuthorityID)
		}
		if !bytes.Equal(sd.DigestHash, ref.DigestHash) || sd.KeyID != ref.KeyID || sd.Algorithm != ref.Algorithm ||
			!bytes.Equal(sd.PublicKeyDER, ref.PublicKeyDER) || !bytes.Equal(sd.Signature, ref.Signature) {
			return nil, fmt.Errorf("%w: digest ref mismatch for %s", ErrInvalidWitness, ref.AuthorityID)
		}
	}
	return byAuthority, nil
}

func verifyWitnessSignatures(payload []byte, sigs []WitnessSignature, trusted map[string]crypto.PublicKey) error {
	for _, sig := range sigs {
		if err := sig.VerifyPayload(payload, trusted); err != nil {
			return err
		}
	}
	return nil
}

func hasSignatureFrom(sigs []WitnessSignature, authorityID string) bool {
	for _, sig := range sigs {
		if sig.AuthorityID == authorityID {
			return true
		}
	}
	return false
}

func verifyEntry(entry Entry, digests map[string]digest.SignedDigest) error {
	switch entry.Class {
	case ClassPresence:
		if entry.PresentAuthority == "" || entry.Absence == nil {
			return ErrInvalidWitness
		}
		for _, inc := range entry.Inclusions {
			if err := verifyInclusionRef(inc, digests); err != nil {
				return err
			}
		}
		absentAuthority, ok := otherAuthority(digests, entry.PresentAuthority)
		if !ok {
			return fmt.Errorf("%w: no absent authority for presence proof", ErrInvalidWitness)
		}
		if !entry.Absence.Verify(digests[absentAuthority].Body.MerkleRoot) {
			return fmt.Errorf("%w: absence proof failed", ErrInvalidWitness)
		}
	case ClassAttributeConflict, ClassPolicyViolation:
		if len(entry.Inclusions) == 0 {
			return ErrInvalidWitness
		}
		for _, inc := range entry.Inclusions {
			if err := verifyInclusionRef(inc, digests); err != nil {
				return err
			}
		}
		if entry.Class == ClassPolicyViolation && entry.Policy == nil {
			return ErrInvalidWitness
		}
	case ClassStaleness:
		if entry.Staleness == nil {
			return ErrInvalidWitness
		}
	default:
		return fmt.Errorf("%w: unknown class %q", ErrInvalidWitness, entry.Class)
	}
	return nil
}

func verifyInclusionRef(ref InclusionProofRef, digests map[string]digest.SignedDigest) error {
	sd, ok := digests[ref.AuthorityID]
	if !ok {
		return fmt.Errorf("%w: missing digest for inclusion authority %s", ErrInvalidWitness, ref.AuthorityID)
	}
	if !ref.Proof.Verify(sd.Body.MerkleRoot) {
		return fmt.Errorf("%w: inclusion proof failed for %s", ErrInvalidWitness, ref.AuthorityID)
	}
	return nil
}

func otherAuthority(digests map[string]digest.SignedDigest, present string) (string, bool) {
	for authorityID := range digests {
		if authorityID != present {
			return authorityID, true
		}
	}
	return "", false
}
