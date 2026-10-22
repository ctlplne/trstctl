// SPDX-License-Identifier: BUSL-1.1

package samltest

import (
	stdcrypto "crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SignEnvelopedXML signs an XML document the way a SAML identity provider does
// (enveloped XMLDSig, RSA/ECDSA-SHA256) with the test IdP material, so tests
// outside the cryptography boundary can produce signed LogoutRequest and
// LogoutResponse messages without touching signature primitives.
func SignEnvelopedXML(key stdcrypto.PrivateKey, cert *x509.Certificate, document []byte) ([]byte, error) {
	signer, ok := key.(stdcrypto.Signer)
	if !ok || cert == nil {
		return nil, errors.New("samltest: signing needs the IdP private key and certificate")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(document); err != nil || doc.Root() == nil {
		return nil, fmt.Errorf("samltest: parse document to sign: %v", err)
	}
	ctx, err := dsig.NewSigningContext(signer, [][]byte{cert.Raw})
	if err != nil {
		return nil, err
	}
	signed, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		return nil, err
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	return out.WriteToBytes()
}
