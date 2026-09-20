// SPDX-License-Identifier: BUSL-1.1

package crypto

import "fmt"

// SelectAlgorithm maps a named core policy profile to the signing algorithm to
// use. The empty profile is treated as "classical"; licensed algorithm
// selection is attached by ee/ code rather than encoded in the MPL core.
func SelectAlgorithm(profile string) (Algorithm, error) {
	switch profile {
	case "", "classical":
		return ECDSAP256, nil
	default:
		return "", fmt.Errorf("crypto: unknown algorithm policy profile %q", profile)
	}
}
