// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// LeafOCSPTarget reads what asking a certificate's own OCSP responder needs
// from the chain kept with it (A245-L3): the leaf (the chain's first
// certificate), the certificate in the chain whose key signed it, and the
// leaf's OCSP responder URLs (its Authority Information Access). issuerDER is
// nil when the chain does not hold the issuer.
func LeafOCSPTarget(chainPEM []byte) (leafDER, issuerDER []byte, ocspURLs []string, err error) {
	var certs []*x509.Certificate
	for rest := chainPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, nil, nil, errors.New("crypto: the stored chain holds a certificate that cannot be parsed")
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, nil, nil, errors.New("crypto: the stored chain holds no certificate")
	}
	leaf := certs[0]
	for _, candidate := range certs[1:] {
		if VerifyCertificateIssuedBy(leaf, candidate) == nil {
			issuerDER = candidate.Raw
			break
		}
	}
	return leaf.Raw, issuerDER, append([]string(nil), leaf.OCSPServer...), nil
}
