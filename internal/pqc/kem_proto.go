// SPDX-License-Identifier: BUSL-1.1

package pqc

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// KEMAlgorithmFromProto maps the neutral licensed algorithm slots in the KEM RPC
// context. These slots are context-scoped: the signing key factory maps the same
// wire slots to signing algorithms, while the KEM custody RPC maps them to ML-KEM.
func KEMAlgorithmFromProto(protoAlg signerpb.Algorithm) (crypto.Algorithm, error) {
	switch protoAlg {
	case signerpb.Algorithm_ALGORITHM_LICENSED_1:
		return MLKEM512, nil
	case signerpb.Algorithm_ALGORITHM_LICENSED_2:
		return MLKEM768, nil
	case signerpb.Algorithm_ALGORITHM_LICENSED_3:
		return MLKEM1024, nil
	default:
		return "", fmt.Errorf("pqc: unsupported KEM algorithm slot %v", protoAlg)
	}
}

func KEMAlgorithmToProto(alg crypto.Algorithm) signerpb.Algorithm {
	switch alg {
	case MLKEM512:
		return signerpb.Algorithm_ALGORITHM_LICENSED_1
	case MLKEM768:
		return signerpb.Algorithm_ALGORITHM_LICENSED_2
	case MLKEM1024:
		return signerpb.Algorithm_ALGORITHM_LICENSED_3
	default:
		return signerpb.Algorithm_ALGORITHM_UNSPECIFIED
	}
}
