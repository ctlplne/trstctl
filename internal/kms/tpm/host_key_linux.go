// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package tpm

import (
	"bytes"
	"encoding/asn1"
	"fmt"

	gotpm "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

var _ HostKeyDevice = (*goTPMDevice)(nil)

// ensureHostSRKLocked returns the persistent storage root key at HostSRKHandle,
// creating it from the standard storage template and persisting it when the
// TPM has none. An SRK another tool provisioned there is used as it is.
func (d *goTPMDevice) ensureHostSRKLocked() (tpmutil.Handle, error) {
	srk := tpmutil.Handle(HostSRKHandle)
	if pub, _, _, err := gotpm.ReadPublic(d.rw, srk); err == nil {
		if pub.Attributes&gotpm.FlagRestricted == 0 || pub.Attributes&gotpm.FlagDecrypt == 0 {
			return 0, fmt.Errorf("tpm: the object at 0x%08x is not a storage key", HostSRKHandle)
		}
		return srk, nil
	}
	primary, _, err := gotpm.CreatePrimary(d.rw, gotpm.HandleOwner, gotpm.PCRSelection{},
		secrettext.String(tpmAuthBytes(d.ownerAuth)), "", tpmStorageParentTemplate())
	if err != nil {
		return 0, fmt.Errorf("tpm: create the storage root key: %w", err)
	}
	defer func() { _ = gotpm.FlushContext(d.rw, primary) }()
	if err := gotpm.EvictControl(d.rw, secrettext.String(tpmAuthBytes(d.ownerAuth)), gotpm.HandleOwner, primary, srk); err != nil {
		return 0, fmt.Errorf("tpm: persist the storage root key at 0x%08x: %w", HostSRKHandle, err)
	}
	return srk, nil
}

// CreateHostKey creates an ECDSA P-256 signing key in the TPM under the
// persistent SRK, with an empty authorization (access to the TPM device is the
// boundary) and fixedTPM, fixedParent and sensitiveDataOrigin set, and returns
// it as a TSS2 private key file with its public key.
func (d *goTPMDevice) CreateHostKey() ([]byte, []byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, nil, fmt.Errorf("tpm: device is closed")
	}
	srk, err := d.ensureHostSRKLocked()
	if err != nil {
		return nil, nil, err
	}
	template, err := tpmSigningTemplate(crypto.ECDSAP256)
	if err != nil {
		return nil, nil, err
	}
	privateBlob, publicBlob, _, _, _, err := gotpm.CreateKey(d.rw, srk, gotpm.PCRSelection{}, "", "", template)
	if err != nil {
		return nil, nil, fmt.Errorf("tpm: create the host key: %w", err)
	}
	defer secret.Wipe(privateBlob)
	pub, err := gotpm.DecodePublic(publicBlob)
	if err != nil {
		return nil, nil, fmt.Errorf("tpm: decode the host key's public area: %w", err)
	}
	der, err := tpmPublicDER(pub, crypto.ECDSAP256)
	if err != nil {
		return nil, nil, err
	}
	file, err := EncodeTSS2PrivateKey(HostSRKHandle, publicBlob, privateBlob)
	if err != nil {
		return nil, nil, err
	}
	return file, der, nil
}

// loadHostKeyLocked loads a host key file under its persistent parent and
// returns the transient handle (flush it) and the key's public area.
func (d *goTPMDevice) loadHostKeyLocked(file []byte) (tpmutil.Handle, gotpm.Public, error) {
	parent, public, private, err := DecodeTSS2PrivateKey(file)
	if err != nil {
		return 0, gotpm.Public{}, err
	}
	defer secret.Wipe(private)
	pub, err := gotpm.DecodePublic(public)
	if err != nil {
		return 0, gotpm.Public{}, fmt.Errorf("tpm: decode the host key's public area: %w", err)
	}
	if pub.Type != gotpm.AlgECC || pub.ECCParameters == nil || pub.ECCParameters.CurveID != gotpm.CurveNISTP256 {
		return 0, gotpm.Public{}, fmt.Errorf("tpm: a host key must be a P-256 signing key")
	}
	handle, _, err := gotpm.Load(d.rw, tpmutil.Handle(parent), "", public, private)
	if err != nil {
		return 0, gotpm.Public{}, fmt.Errorf("tpm: load the host key under 0x%08x: %w", parent, err)
	}
	return handle, pub, nil
}

// HostKeyPublicDER reads a host key file's public key from its public area.
func (d *goTPMDevice) HostKeyPublicDER(file []byte) ([]byte, error) {
	_, public, private, err := DecodeTSS2PrivateKey(file)
	if err != nil {
		return nil, err
	}
	secret.Wipe(private)
	pub, err := gotpm.DecodePublic(public)
	if err != nil {
		return nil, fmt.Errorf("tpm: decode the host key's public area: %w", err)
	}
	if pub.Type != gotpm.AlgECC || pub.ECCParameters == nil || pub.ECCParameters.CurveID != gotpm.CurveNISTP256 {
		return nil, fmt.Errorf("tpm: a host key must be a P-256 signing key")
	}
	return tpmPublicDER(pub, crypto.ECDSAP256)
}

// SignWithHostKey signs a SHA-256 digest with a host key file's key, which
// the TPM loads for the signature only.
func (d *goTPMDevice) SignWithHostKey(file, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("tpm: a host key signs a SHA-256 digest")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, fmt.Errorf("tpm: device is closed")
	}
	handle, _, err := d.loadHostKeyLocked(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gotpm.FlushContext(d.rw, handle) }()
	sig, err := gotpm.Sign(d.rw, handle, "", digest, nil, &gotpm.SigScheme{Alg: gotpm.AlgECDSA, Hash: gotpm.AlgSHA256})
	if err != nil {
		return nil, fmt.Errorf("tpm: sign with the host key: %w", err)
	}
	if sig.ECC == nil {
		return nil, fmt.Errorf("tpm: the device returned no ECDSA signature")
	}
	return asn1.Marshal(struct{ R, S any }{R: sig.ECC.R, S: sig.ECC.S})
}

// CertifyHostKey has the TPM certify a host key file's key (TPM2_Certify)
// under the persistent attestation key signerHandle: the certInfo comes from
// the device and states the key's attributes, signed by the resident AIK.
func (d *goTPMDevice) CertifyHostKey(file []byte, signerHandle string, qualifyingData, signerAuth []byte) (crypto.EdgeTPMCertification, error) {
	if len(qualifyingData) != 32 {
		return crypto.EdgeTPMCertification{}, fmt.Errorf("tpm: host key certification requires a SHA-256 qualifying digest")
	}
	lockedSignerAuth, err := lockTPMAuth(signerAuth)
	if err != nil {
		return crypto.EdgeTPMCertification{}, fmt.Errorf("tpm: protect attestation key authorization: %w", err)
	}
	if lockedSignerAuth != nil {
		defer lockedSignerAuth.Destroy()
	}
	signer, err := parseTPMHandle(signerHandle)
	if err != nil {
		return crypto.EdgeTPMCertification{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return crypto.EdgeTPMCertification{}, fmt.Errorf("tpm: device is closed")
	}
	object, objectPublic, err := d.loadHostKeyLocked(file)
	if err != nil {
		return crypto.EdgeTPMCertification{}, err
	}
	defer func() { _ = gotpm.FlushContext(d.rw, object) }()
	signerPublic, _, _, err := gotpm.ReadPublic(d.rw, signer)
	if err != nil {
		return crypto.EdgeTPMCertification{}, fmt.Errorf("tpm: read attestation key: %w", err)
	}
	if signerPublic.Type != gotpm.AlgECC || signerPublic.ECCParameters == nil || signerPublic.ECCParameters.CurveID != gotpm.CurveNISTP256 {
		return crypto.EdgeTPMCertification{}, fmt.Errorf("tpm: the attestation key must be a P-256 signing key")
	}
	pubArea, err := objectPublic.Encode()
	if err != nil {
		return crypto.EdgeTPMCertification{}, fmt.Errorf("tpm: encode host key public area: %w", err)
	}
	objectDER, err := tpmPublicDER(objectPublic, crypto.ECDSAP256)
	if err != nil {
		return crypto.EdgeTPMCertification{}, err
	}
	signerDER, err := tpmPublicDER(signerPublic, crypto.ECDSAP256)
	if err != nil {
		return crypto.EdgeTPMCertification{}, err
	}
	attest, signatureWire, err := gotpm.CertifyEx(d.rw, "", secrettext.String(tpmAuthBytes(lockedSignerAuth)), object, signer,
		qualifyingData, gotpm.SigScheme{Alg: gotpm.AlgECDSA, Hash: gotpm.AlgSHA256})
	if err != nil {
		return crypto.EdgeTPMCertification{}, fmt.Errorf("tpm: TPM2_Certify: %w", err)
	}
	signature, err := gotpm.DecodeSignature(bytes.NewBuffer(signatureWire))
	if err != nil || signature.ECC == nil || signature.Alg != gotpm.AlgECDSA || signature.ECC.HashAlg != gotpm.AlgSHA256 {
		return crypto.EdgeTPMCertification{}, fmt.Errorf("tpm: TPM2_Certify returned an invalid ECDSA-SHA256 signature")
	}
	signatureDER, err := asn1.Marshal(struct{ R, S any }{R: signature.ECC.R, S: signature.ECC.S})
	if err != nil {
		return crypto.EdgeTPMCertification{}, err
	}
	return crypto.EdgeTPMCertification{
		PublicArea: pubArea, ObjectPublicKeyDER: objectDER, SignerPublicKeyDER: signerDER,
		CertInfo: attest, SignatureDER: signatureDER,
	}, nil
}
