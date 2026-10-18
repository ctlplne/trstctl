// SPDX-License-Identifier: BUSL-1.1

package crypto

// EdgeTPMCertification contains only public TPM2_Certify output. It is a
// backend-neutral result so the signer-facing TPM backend does not import the
// WebAuthn parser or its dependency tree.
type EdgeTPMCertification struct {
	PublicArea         []byte
	ObjectPublicKeyDER []byte
	SignerPublicKeyDER []byte
	CertInfo           []byte
	SignatureDER       []byte
}

// EdgeTPMCertifier asks the device to certify one persistent edge signing
// object under a distinct TPM-held attestation key. Neither private key is
// returned to the caller.
type EdgeTPMCertifier interface {
	CertifyEdgeKey(objectHandle, signerHandle string, qualifyingData, signerAuth []byte) (EdgeTPMCertification, error)
}
