// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// X509SVIDCheck is what a workload learns from a Workload API X.509-SVID it
// has checked.
type X509SVIDCheck struct {
	SPIFFEID string
	NotAfter time.Time
	// ChainLength counts x509_svid's certificates, leaf first; Authorities
	// counts the trust bundle's.
	ChainLength int
	Authorities int
}

// VerifyX509SVID checks an X.509-SVID the way a workload that receives one
// does: chainDER (x509_svid: the leaf, then any intermediates, as concatenated
// DER) chains at now to an authority in bundleDER (the trust domain's bundle,
// concatenated DER); the leaf carries exactly one canonical SPIFFE ID; and
// keyPKCS8 (x509_svid_key) is the leaf's private key. The parsed key is wiped
// after the comparison; the caller wipes keyPKCS8.
func VerifyX509SVID(chainDER, bundleDER, keyPKCS8 []byte, now time.Time) (X509SVIDCheck, error) {
	chain, err := x509.ParseCertificates(chainDER)
	if err != nil {
		return X509SVIDCheck{}, fmt.Errorf("crypto: parse the SVID chain: %w", err)
	}
	if len(chain) == 0 {
		return X509SVIDCheck{}, errors.New("crypto: the SVID chain is empty")
	}
	authorities, err := x509.ParseCertificates(bundleDER)
	if err != nil {
		return X509SVIDCheck{}, fmt.Errorf("crypto: parse the trust bundle: %w", err)
	}
	if len(authorities) == 0 {
		return X509SVIDCheck{}, errors.New("crypto: the trust bundle is empty")
	}
	leaf := chain[0]
	id, err := SPIFFEIDFromCert(leaf.Raw)
	if err != nil {
		return X509SVIDCheck{}, err
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, ca := range authorities {
		roots.AddCert(ca)
	}
	for _, ca := range chain[1:] {
		intermediates.AddCert(ca)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return X509SVIDCheck{}, fmt.Errorf("crypto: the SVID does not chain to the trust bundle: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyPKCS8)
	if err != nil {
		return X509SVIDCheck{}, fmt.Errorf("crypto: parse the SVID's private key: %w", err)
	}
	defer wipeStdlibKey(key)
	signer, ok := key.(crypto.Signer)
	if !ok {
		return X509SVIDCheck{}, fmt.Errorf("crypto: the SVID's private key (%T) is not a signing key", key)
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return X509SVIDCheck{}, fmt.Errorf("crypto: encode the SVID key's public half: %w", err)
	}
	if !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
		return X509SVIDCheck{}, errors.New("crypto: the private key handed over is not the SVID's")
	}
	return X509SVIDCheck{SPIFFEID: id, NotAfter: leaf.NotAfter, ChainLength: len(chain), Authorities: len(authorities)}, nil
}
