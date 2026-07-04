// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// NewSignerKeyFactory supplies proprietary PQC key implementations to the
// isolated signer process through signing's compile-time DI seam.
func NewSignerKeyFactory() signing.KeyFactory {
	return signerKeyFactory{}
}

type signerKeyFactory struct{}

func (signerKeyFactory) GenerateSigningKey(alg crypto.Algorithm) (signing.Key, error) {
	switch alg {
	case MLDSA44, MLDSA65, MLDSA87, HybridEd25519Dilithium3:
		return GenerateKey(alg)
	case SLHDSA128s, SLHDSA128f, SLHDSA192s, SLHDSA256s:
		return GenerateSLHDSAKey(alg)
	default:
		return crypto.GenerateLockedKey(alg)
	}
}

func (f signerKeyFactory) GenerateSigningKeyFromProto(protoAlg signerpb.Algorithm) (signing.Key, error) {
	alg, err := algorithmFromProto(protoAlg)
	if err != nil {
		return nil, err
	}
	return f.GenerateSigningKey(alg)
}

func (signerKeyFactory) SigningKeyFromSealedBytes(protoAlg signerpb.Algorithm, privateKey []byte) (signing.Key, error) {
	if protoAlg == signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		return crypto.LockedKeyFromPKCS8(privateKey)
	}
	alg, err := algorithmFromProto(protoAlg)
	if err != nil {
		return nil, err
	}
	switch alg {
	case MLDSA44, MLDSA65, MLDSA87, HybridEd25519Dilithium3:
		return NewSignerFromPrivateKey(alg, privateKey)
	case SLHDSA128s, SLHDSA128f, SLHDSA192s, SLHDSA256s:
		return NewSLHDSAKeyFromPrivateKey(alg, privateKey)
	default:
		return crypto.NewLockedSignerFromPKCS8(alg, privateKey)
	}
}

func (signerKeyFactory) ProtoFromAlgorithm(alg crypto.Algorithm) signerpb.Algorithm {
	switch alg {
	case MLDSA44:
		return signerpb.Algorithm_ALGORITHM_LICENSED_1
	case MLDSA65:
		return signerpb.Algorithm_ALGORITHM_LICENSED_2
	case MLDSA87:
		return signerpb.Algorithm_ALGORITHM_LICENSED_3
	case SLHDSA128s:
		return signerpb.Algorithm_ALGORITHM_LICENSED_4
	case SLHDSA128f:
		return signerpb.Algorithm_ALGORITHM_LICENSED_5
	case SLHDSA192s:
		return signerpb.Algorithm_ALGORITHM_LICENSED_6
	case SLHDSA256s:
		return signerpb.Algorithm_ALGORITHM_LICENSED_7
	case crypto.RSA2048:
		return signerpb.Algorithm_ALGORITHM_RSA_2048
	case crypto.RSA3072:
		return signerpb.Algorithm_ALGORITHM_RSA_3072
	case crypto.RSA4096:
		return signerpb.Algorithm_ALGORITHM_RSA_4096
	case crypto.ECDSAP256:
		return signerpb.Algorithm_ALGORITHM_ECDSA_P256
	case crypto.ECDSAP384:
		return signerpb.Algorithm_ALGORITHM_ECDSA_P384
	case crypto.ECDSAP521:
		return signerpb.Algorithm_ALGORITHM_ECDSA_P521
	default:
		return signerpb.Algorithm_ALGORITHM_UNSPECIFIED
	}
}

func algorithmFromProto(a signerpb.Algorithm) (crypto.Algorithm, error) {
	switch a {
	case signerpb.Algorithm_ALGORITHM_RSA_2048:
		return crypto.RSA2048, nil
	case signerpb.Algorithm_ALGORITHM_RSA_3072:
		return crypto.RSA3072, nil
	case signerpb.Algorithm_ALGORITHM_RSA_4096:
		return crypto.RSA4096, nil
	case signerpb.Algorithm_ALGORITHM_ECDSA_P256:
		return crypto.ECDSAP256, nil
	case signerpb.Algorithm_ALGORITHM_ECDSA_P384:
		return crypto.ECDSAP384, nil
	case signerpb.Algorithm_ALGORITHM_ECDSA_P521:
		return crypto.ECDSAP521, nil
	case signerpb.Algorithm_ALGORITHM_LICENSED_1:
		return MLDSA44, nil
	case signerpb.Algorithm_ALGORITHM_LICENSED_2:
		return MLDSA65, nil
	case signerpb.Algorithm_ALGORITHM_LICENSED_3:
		return MLDSA87, nil
	case signerpb.Algorithm_ALGORITHM_LICENSED_4:
		return SLHDSA128s, nil
	case signerpb.Algorithm_ALGORITHM_LICENSED_5:
		return SLHDSA128f, nil
	case signerpb.Algorithm_ALGORITHM_LICENSED_6:
		return SLHDSA192s, nil
	case signerpb.Algorithm_ALGORITHM_LICENSED_7:
		return SLHDSA256s, nil
	default:
		return "", fmt.Errorf("pqc: unsupported signer algorithm %v", a)
	}
}
