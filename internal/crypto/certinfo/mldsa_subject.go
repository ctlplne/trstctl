// SPDX-License-Identifier: BUSL-1.1
package certinfo

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// inspectMLDSASubject identifies the public key, not the issuer's signature.
// RFC 9881 sections 2 and 4 require absent parameters and a byte-aligned raw
// public key of the parameter set's exact size. Unknown OIDs stay unknown.
// The label asserts no chain trust or key ownership. Encoded key length is not
// security strength: callers leave PublicKeyBits zero for these algorithms.
func inspectMLDSASubject(raw []byte) (string, error) {
	if len(raw) > 1<<20 {
		return "", errors.New("certinfo: subject public key exceeds inventory bound")
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(raw, &spki)
	if err != nil || len(rest) != 0 {
		return "", errors.New("certinfo: malformed subject public key encoding")
	}
	algorithm, size := "", 0
	switch spki.Algorithm.Algorithm.String() {
	case "2.16.840.1.101.3.4.3.17":
		algorithm, size = "ML-DSA-44", 1312
	case "2.16.840.1.101.3.4.3.18":
		algorithm, size = "ML-DSA-65", 1952
	case "2.16.840.1.101.3.4.3.19":
		algorithm, size = "ML-DSA-87", 2592
	default:
		return "", nil
	}
	canonical, err := asn1.Marshal(spki)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", errors.New("certinfo: ML-DSA subject public key has extra or noncanonical fields")
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 {
		return "", errors.New("certinfo: ML-DSA subject parameters must be absent")
	}
	if len(spki.PublicKey.Bytes) != size || spki.PublicKey.BitLength != size*8 {
		return "", errors.New("certinfo: ML-DSA subject public key has invalid size or padding")
	}
	return algorithm, nil
}
