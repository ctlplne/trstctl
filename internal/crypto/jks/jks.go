// Package jks encodes a private key together with its certificate chain as a
// Java KeyStore (the legacy JKS format, magic 0xFEEDFEED) under a named alias.
// It complements internal/crypto/pfx (PKCS#12), giving the Java keystore
// connector both of the formats Java applications use.
//
// It is part of the crypto boundary (AN-3): the JKS format and its SHA-1-based
// key protection are handled by a vendored library (keystore-go); this package
// is the only place outside the rest of internal/crypto that imports it, and it
// is not linked into the signing service. Key material is handled as []byte /
// DER, never as a string (AN-8).
package jks

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"

	"trstctl.com/trstctl/internal/crypto/detrand"
)

// epoch is the fixed entry creation time used by EncodeDeterministic so the
// timestamp does not vary between encodes.
var epoch = time.Unix(0, 0).UTC()

// EncodeDeterministic packages a PEM private key and PEM certificate chain (leaf
// first) into a JKS keystore stored under alias and protected by password. All
// randomness (the key-protection salt) and the entry timestamp are derived
// deterministically from the credential, so the same input always encodes to
// byte-identical output — making a keystore deployment idempotent (AN-5/AN-6).
// The salt is not secret (it is stored in the keystore in the clear) and remains
// unique per distinct credential, so the protection is unchanged.
func EncodeDeterministic(keyPEM, certChainPEM []byte, password, alias string) ([]byte, error) {
	keyDER, err := pkcs8DER(keyPEM)
	if err != nil {
		return nil, err
	}
	chain, err := certChain(certChainPEM)
	if err != nil {
		return nil, err
	}

	ks := keystore.New(
		keystore.WithCustomRandomNumberGenerator(
			detrand.New([]byte("trstctl/jks/v1"), []byte(password), []byte(alias), keyPEM, certChainPEM),
		),
		keystore.WithOrderedAliases(),
	)
	entry := keystore.PrivateKeyEntry{
		CreationTime:     epoch,
		PrivateKey:       keyDER,
		CertificateChain: chain,
	}
	if err := ks.SetPrivateKeyEntry(alias, entry, []byte(password)); err != nil {
		return nil, fmt.Errorf("jks: set entry: %w", err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		return nil, fmt.Errorf("jks: store: %w", err)
	}
	return buf.Bytes(), nil
}

// Decode loads a JKS keystore with password and returns the private key and
// certificate chain (leaf first) under alias as PEM. It is the inverse of
// EncodeDeterministic, used to verify a written keystore.
func Decode(jksData []byte, password, alias string) (keyPEM, certChainPEM []byte, err error) {
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(jksData), []byte(password)); err != nil {
		return nil, nil, fmt.Errorf("jks: load: %w", err)
	}
	entry, err := ks.GetPrivateKeyEntry(alias, []byte(password))
	if err != nil {
		return nil, nil, fmt.Errorf("jks: get entry %q: %w", alias, err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: entry.PrivateKey})
	for _, c := range entry.CertificateChain {
		certChainPEM = append(certChainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Content})...)
	}
	return keyPEM, certChainPEM, nil
}

// pkcs8DER returns the private key as PKCS#8 DER (the form a JKS key entry
// stores), converting from PKCS#1 or SEC1 if necessary.
func pkcs8DER(keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("jks: no PEM private-key block")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return block.Bytes, nil // already PKCS#8
	}
	var key any
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		key = k
	} else {
		return nil, errors.New("jks: unrecognized private-key format")
	}
	return x509.MarshalPKCS8PrivateKey(key)
}

func certChain(certChainPEM []byte) ([]keystore.Certificate, error) {
	var chain []keystore.Certificate
	rest := certChainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		chain = append(chain, keystore.Certificate{Type: "X509", Content: block.Bytes})
	}
	if len(chain) == 0 {
		return nil, errors.New("jks: no certificate in chain")
	}
	return chain, nil
}
