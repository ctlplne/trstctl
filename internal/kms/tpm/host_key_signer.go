// SPDX-License-Identifier: BUSL-1.1

package tpm

import (
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

// HostKeySigner is a crypto.DigestSigner over a host key file's key (TPM-O1):
// every signature is the TPM's, with the key loaded for that signature only.
// It holds the TSS2 file (the TPM's wrapping, useless without this TPM) and
// the public key.
func HostKeySigner(dev HostKeyDevice, file, publicKeyDER []byte) crypto.DigestSigner {
	return hostKeySigner{dev: dev, file: append([]byte(nil), file...),
		public: crypto.PublicKey{Algorithm: crypto.ECDSAP256, DER: append([]byte(nil), publicKeyDER...)}}
}

type hostKeySigner struct {
	dev    HostKeyDevice
	file   []byte
	public crypto.PublicKey
}

func (s hostKeySigner) Public() crypto.PublicKey    { return s.public }
func (s hostKeySigner) Algorithm() crypto.Algorithm { return crypto.ECDSAP256 }

func (s hostKeySigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	if opts.Hash != "" && opts.Hash != crypto.SHA256 {
		return nil, errors.New("tpm: a host key signs SHA-256 digests")
	}
	if s.dev == nil {
		return nil, errors.New("tpm: no TPM for the host key")
	}
	return s.dev.SignWithHostKey(s.file, digest)
}
