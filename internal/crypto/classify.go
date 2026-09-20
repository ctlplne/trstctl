// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"fmt"
	"strings"
)

// Classification describes an algorithm for the crypto inventory: its family,
// whether it signs or encapsulates keys, and whether current public algorithms
// are expected to weaken it.
type Classification struct {
	Algorithm         Algorithm
	Family            string // RSA, ECDSA, Ed25519, or another linked backend family.
	Kind              string // "signature" or "kem"
	QuantumVulnerable bool   // breakable by a cryptographically-relevant quantum computer
	PostQuantum       bool   // designed to resist quantum attacks
}

// licensedClassifier recognizes algorithm labels the core deliberately does
// not know. It is installed exactly once, from the tagged attach seam
// (cmd/trstctl/ee_attach.go, AN-9), before serving begins; nil keeps the
// strict core behavior, so an unlicensed binary fails closed on those labels.
var licensedClassifier func(Algorithm) (Classification, bool)

// InstallLicensedAlgorithmClassifier registers the licensed algorithm
// classifier. Call it once at process attach time, never per request.
func InstallLicensedAlgorithmClassifier(fn func(Algorithm) (Classification, bool)) {
	licensedClassifier = fn
}

// Classify returns the classification of an algorithm, or an error if it is
// unknown. An installed licensed classifier is consulted for algorithms the
// core does not recognize before failing closed.
func Classify(a Algorithm) (Classification, error) {
	switch a {
	case RSA2048, RSA3072, RSA4096:
		return Classification{Algorithm: a, Family: "RSA", Kind: "signature", QuantumVulnerable: true}, nil
	case ECDSAP256, ECDSAP384, ECDSAP521:
		return Classification{Algorithm: a, Family: "ECDSA", Kind: "signature", QuantumVulnerable: true}, nil
	case Ed25519:
		return Classification{Algorithm: a, Family: "Ed25519", Kind: "signature", QuantumVulnerable: true}, nil
	default:
		if licensedClassifier != nil {
			if c, ok := licensedClassifier(a); ok {
				return c, nil
			}
		}
		return Classification{}, fmt.Errorf("crypto: unknown algorithm %q", a)
	}
}

// ClassifyAlgorithmLabel accepts the labels exposed by served inventory and
// certificate profiles. RSA/ECDSA are compatibility family labels emitted by
// CSR/certificate inspection; exact algorithm labels are classified by Classify.
func ClassifyAlgorithmLabel(label string) (Classification, error) {
	a := Algorithm(strings.TrimSpace(label))
	switch a {
	case "":
		return Classification{}, fmt.Errorf("crypto: empty algorithm label")
	case Algorithm("RSA"):
		return Classification{Algorithm: a, Family: "RSA", Kind: "signature", QuantumVulnerable: true}, nil
	case Algorithm("ECDSA"):
		return Classification{Algorithm: a, Family: "ECDSA", Kind: "signature", QuantumVulnerable: true}, nil
	default:
		return Classify(a)
	}
}
