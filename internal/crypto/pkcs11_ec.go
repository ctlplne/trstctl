// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// EC keys in a PKCS#11 token (P9-L3). A token describes a curve by its
// CKA_EC_PARAMS (the DER of the curve's OID), returns the public point as
// CKA_EC_POINT (the DER OCTET STRING of the uncompressed SEC 1 point; some
// tokens return the bare point) and signs with CKM_ECDSA as the raw r||s
// pair. These helpers turn those into the PKIX and ASN.1 forms the rest of
// trstctl uses, inside the AN-3 boundary, so a PKCS#11 adapter never imports
// crypto/ecdsa, crypto/elliptic or crypto/x509 itself.

var (
	oidCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

// ecCurveFor names an EC algorithm's curve and its coordinate size.
func ecCurveFor(alg Algorithm) (curve string, size int, oid asn1.ObjectIdentifier, err error) {
	switch alg {
	case ECDSAP256:
		return "P-256", 32, oidCurveP256, nil
	case ECDSAP384:
		return "P-384", 48, oidCurveP384, nil
	default:
		return "", 0, nil, fmt.Errorf("crypto: %q is not an EC algorithm a PKCS#11 token generates here", alg)
	}
}

// IsPKCS11ECAlgorithm reports whether alg is an EC algorithm the PKCS#11
// adapter generates.
func IsPKCS11ECAlgorithm(alg Algorithm) bool {
	_, _, _, err := ecCurveFor(alg)
	return err == nil
}

// PKCS11ECParams is the CKA_EC_PARAMS value that selects alg's curve.
func PKCS11ECParams(alg Algorithm) ([]byte, error) {
	_, _, oid, err := ecCurveFor(alg)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(oid)
}

// ECDSAPublicKeyDERFromPKCS11 validates a token's CKA_EC_PARAMS and
// CKA_EC_POINT and returns the PKIX SubjectPublicKeyInfo, with the algorithm
// the curve names.
func ECDSAPublicKeyDERFromPKCS11(ecParams, ecPoint []byte) ([]byte, Algorithm, error) {
	var oid asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(ecParams, &oid); err != nil || len(rest) != 0 {
		return nil, "", errors.New("crypto: CKA_EC_PARAMS is not a named curve")
	}
	var alg Algorithm
	switch {
	case oid.Equal(oidCurveP256):
		alg = ECDSAP256
	case oid.Equal(oidCurveP384):
		alg = ECDSAP384
	default:
		return nil, "", fmt.Errorf("crypto: CKA_EC_PARAMS names curve %s, not P-256 or P-384", oid)
	}
	curve, size, _, _ := ecCurveFor(alg)
	point := ecPoint
	var wrapped []byte
	if rest, err := asn1.Unmarshal(ecPoint, &wrapped); err == nil && len(rest) == 0 {
		point = wrapped
	}
	if len(point) != 1+2*size || point[0] != 4 {
		return nil, "", errors.New("crypto: CKA_EC_POINT is not an uncompressed point on the curve")
	}
	der, err := ECDSAPublicKeyDERFromComponents(curve, point[1:1+size], point[1+size:])
	if err != nil {
		return nil, "", err
	}
	return der, alg, nil
}

// ECDSASignatureDERFromRaw turns a CKM_ECDSA signature (r||s, each the
// curve's coordinate size) into the ASN.1 form trstctl verifies and stores.
func ECDSASignatureDERFromRaw(raw []byte, alg Algorithm) ([]byte, error) {
	_, size, _, err := ecCurveFor(alg)
	if err != nil {
		return nil, err
	}
	if len(raw) != 2*size {
		return nil, fmt.Errorf("crypto: an %s signature is %d bytes, not %d", alg, 2*size, len(raw))
	}
	r, s := new(big.Int).SetBytes(raw[:size]), new(big.Int).SetBytes(raw[size:])
	if r.Sign() == 0 || s.Sign() == 0 {
		return nil, errors.New("crypto: an ECDSA signature value is zero")
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}
