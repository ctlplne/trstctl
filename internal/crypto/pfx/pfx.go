// Package pfx encodes a private key together with its certificate chain as
// PKCS#12 (PFX) — the package format the Windows certificate store imports to
// install a certificate with its private key (PFXImportCertStore).
//
// It is part of the crypto boundary (AN-3): it is the only place outside the
// rest of internal/crypto that parses keys and certificates, and it is not
// linked into the signing service. Key material is handled as []byte / parsed
// key objects, never as a string (AN-8).
package pfx

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"trstctl.com/trstctl/internal/crypto/detrand"
)

// EncodeTransient packages the key and certificate chain into a PKCS#12 blob
// protected by a freshly generated random password, returning both. It is for
// handing a PFX straight to an OS importer (for example Windows
// PFXImportCertStore): the blob and password live only for that call and are
// then discarded, so the password is never persisted or transmitted.
func EncodeTransient(keyPEM, certChainPEM []byte) (pfxDER []byte, password string, err error) {
	var b [16]byte
	if _, err = rand.Read(b[:]); err != nil {
		return nil, "", err
	}
	password = hex.EncodeToString(b[:])
	pfxDER, err = Encode(keyPEM, certChainPEM, password)
	return pfxDER, password, err
}

// Encode packages a PEM private key and a PEM certificate chain (leaf first)
// into a password-protected PKCS#12 blob. The password protects the transient
// PFX as it is handed to the OS importer; callers discard it immediately.
func Encode(keyPEM, certChainPEM []byte, password string) ([]byte, error) {
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, cas, err := parseCertChain(certChainPEM)
	if err != nil {
		return nil, err
	}
	return pkcs12.Modern.Encode(key, leaf, cas, password)
}

// EncodeDeterministic is like Encode but derives the PKCS#12 randomness (the
// PBKDF salt and encryption IV) deterministically from the credential and
// password, so the same input always encodes to byte-identical output. This
// makes a keystore deployment idempotent (AN-5/AN-6): redelivering the same
// renewal rewrites identical bytes. It is sound because PKCS#12 salts are not
// secret — they are stored in the blob in the clear — and remain unique per
// distinct credential; the password protection is unchanged.
func EncodeDeterministic(keyPEM, certChainPEM []byte, password string) ([]byte, error) {
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, cas, err := parseCertChain(certChainPEM)
	if err != nil {
		return nil, err
	}
	r := detrand.New([]byte("trstctl/pfx/v1"), []byte(password), keyPEM, certChainPEM)
	return pkcs12.Modern.WithRand(r).Encode(key, leaf, cas, password)
}

// Decode parses a PKCS#12 blob with password and returns the private key and
// certificate chain (leaf first) as PEM. It is the inverse of Encode, used to
// verify a written keystore.
func Decode(pfxData []byte, password string) (keyPEM, certChainPEM []byte, err error) {
	key, cert, caCerts, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, nil, fmt.Errorf("pfx: decode: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("pfx: marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certChainPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	for _, ca := range caCerts {
		certChainPEM = append(certChainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	}
	return keyPEM, certChainPEM, nil
}

func parsePrivateKey(keyPEM []byte) (any, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("pfx: no PEM private-key block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k.(type) {
		case *ecdsa.PrivateKey, *rsa.PrivateKey:
			return k, nil
		default:
			return k, nil
		}
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("pfx: unrecognized private-key format")
}

func parseCertChain(certPEM []byte) (leaf *x509.Certificate, cas []*x509.Certificate, err error) {
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return nil, nil, fmt.Errorf("pfx: parse certificate: %w", perr)
		}
		if leaf == nil {
			leaf = c
		} else {
			cas = append(cas, c)
		}
	}
	if leaf == nil {
		return nil, nil, errors.New("pfx: no certificate in chain")
	}
	return leaf, cas, nil
}
