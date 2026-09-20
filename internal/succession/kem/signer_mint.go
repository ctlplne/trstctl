// SPDX-License-Identifier: BUSL-1.1

package kem

import (
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession"
)

// signer_mint.go mints a Variant-B (publicly verifiable) KEM succession THROUGH the
// signer custody boundary (PCAS-claim-15, INT-12). A KEM key cannot sign, so a KEM
// succession is a normal dual-signed succession to a paired epoch-bound SIGNING key
// that binds the KEM public key. The point of doing it through the signer is custody:
// the signer generates BOTH the paired signing key and the ML-KEM successor key inside
// its boundary, and only PUBLIC material — the paired public key, the two signatures,
// the KEM public key, and the binding — crosses out. The KEM private key stays in the
// signer for later decapsulation and re-wrap; it is never exported.

// SignerKEMCustody is the signer's key custody for a through-signer KEM succession. A
// production implementation is backed by the signer's keystore (paired signing key via
// the SuccessorKeyStore seam; the ML-KEM key generated and retained inside the signer).
type SignerKEMCustody interface {
	// GeneratePairedSigningKey generates the paired epoch-bound signing key inside the
	// signer under handle and returns a Signer view whose private key never leaves the
	// signer.
	GeneratePairedSigningKey(handle string) (crypto.Signer, error)
	// GenerateKEMSuccessor generates the ML-KEM successor inside the signer under handle
	// and returns ONLY its public key (SubjectPublicKeyInfo DER). The KEM private key is
	// retained in the signer for decapsulation / re-wrap and is never returned.
	GenerateKEMSuccessor(handle, kemAlg string) (kemPubDER []byte, err error)
}

// MintPairedThroughSigner mints a Variant-B KEM succession using the signer's custody.
// The predecessor (also held in the signer) attests the commitment; the signer-generated
// paired signing key contributes the possession signature and binds the KEM public key.
// The returned PairedRecord carries only PUBLIC material — VerifyPaired confirms it
// offline — and the KEM private key never crosses the boundary (INT-12).
func MintPairedThroughSigner(fields succession.CommitmentFields, predecessor crypto.Signer, custody SignerKEMCustody, pairedHandle, kemHandle, kemAlg string) (PairedRecord, error) {
	paired, err := custody.GeneratePairedSigningKey(pairedHandle)
	if err != nil {
		return PairedRecord{}, err
	}
	fields.SuccessorAlg = paired.Algorithm()
	fields.SuccessorPub = paired.Public().DER

	commitment, err := succession.Commit(fields)
	if err != nil {
		return PairedRecord{}, err
	}
	predSig, err := predecessor.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return PairedRecord{}, err
	}
	possSig, err := paired.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return PairedRecord{}, err
	}
	base := succession.SuccessionRecord{
		Fields:         fields,
		PredecessorAtt: predSig,
		Possession:     succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: possSig},
	}

	// The KEM successor is generated inside the signer; only its public key crosses out.
	kemPub, err := custody.GenerateKEMSuccessor(kemHandle, kemAlg)
	if err != nil {
		return PairedRecord{}, err
	}
	binding, err := SignKEMBinding(paired, commitment, kemAlg, kemPub)
	if err != nil {
		return PairedRecord{}, err
	}
	return PairedRecord{Base: base, KEMAlg: kemAlg, KEMPub: kemPub, Binding: binding}, nil
}
