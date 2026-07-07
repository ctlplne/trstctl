// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// Key is the private-key handle the signer process keeps in RAM. It is a digest
// signer plus an explicit destroy hook, so every implementation shares the same
// AN-4 storage path while the concrete key backend is supplied at assembly time.
type Key interface {
	crypto.DigestSigner
	Destroy()
}

type signerKey = Key

type privateKeyBytesExporter interface {
	PrivateKeyBytes() ([]byte, error)
}

// KeyFactory creates and restores signer-held keys. The core factory supports
// only the MPL algorithms; proprietary backends are injected from the tagged EE
// attach seam so core never imports ee/ or proprietary key implementations.
type KeyFactory interface {
	GenerateSigningKey(crypto.Algorithm) (Key, error)
	GenerateSigningKeyFromProto(signerpb.Algorithm) (Key, error)
	SigningKeyFromSealedBytes(signerpb.Algorithm, []byte) (Key, error)
	ProtoFromAlgorithm(crypto.Algorithm) signerpb.Algorithm
}

type defaultKeyFactory struct{}

// NewDefaultKeyFactory returns the core default key factory (MPL algorithms only). It is
// the factory NewServer installs when none is supplied via WithKeyFactory. It is exported
// so a caller that wants to WRAP the default factory (for example to instrument or count
// key generations while still producing real keys) can delegate to it without importing an
// unexported type.
func NewDefaultKeyFactory() KeyFactory { return defaultKeyFactory{} }

func (defaultKeyFactory) GenerateSigningKey(alg crypto.Algorithm) (Key, error) {
	return crypto.GenerateLockedKey(alg)
}

func (f defaultKeyFactory) GenerateSigningKeyFromProto(protoAlg signerpb.Algorithm) (Key, error) {
	alg, err := algorithmFromProto(protoAlg)
	if err != nil {
		return nil, err
	}
	return f.GenerateSigningKey(alg)
}

func (defaultKeyFactory) SigningKeyFromSealedBytes(protoAlg signerpb.Algorithm, privateKey []byte) (Key, error) {
	if protoAlg == signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		return crypto.LockedKeyFromPKCS8(privateKey)
	}
	alg, err := algorithmFromProto(protoAlg)
	if err != nil {
		return nil, err
	}
	return crypto.NewLockedSignerFromPKCS8(alg, privateKey)
}

func (defaultKeyFactory) ProtoFromAlgorithm(alg crypto.Algorithm) signerpb.Algorithm {
	return algorithmToProto(alg)
}

func privateKeyBytesForSealing(key signerKey) ([]byte, error) {
	if locked, ok := key.(*crypto.LockedSigner); ok {
		return locked.PKCS8()
	}
	if exporter, ok := key.(privateKeyBytesExporter); ok {
		return exporter.PrivateKeyBytes()
	}
	return nil, fmt.Errorf("signing: key type %T cannot export sealed private bytes", key)
}
