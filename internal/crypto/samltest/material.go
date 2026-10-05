// SPDX-License-Identifier: BUSL-1.1

// Package samltest generates ephemeral SAML IdP material for integration tests.
// It lives under internal/crypto so tests outside the boundary do not import
// crypto/x509 or key-generation primitives directly (AN-3).
package samltest

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"trstctl.com/trstctl/internal/crypto/secretfile"
)

// NewIdentityProviderMaterial returns a throwaway RSA key and self-signed
// certificate suitable for a mock SAML IdP.
func NewIdentityProviderMaterial(commonName string) (stdcrypto.PrivateKey, *x509.Certificate, error) {
	return newIdentityProviderMaterial(commonName, 24*time.Hour)
}

func newIdentityProviderMaterial(commonName string, ttl time.Duration) (stdcrypto.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

// LoadOrCreateIdentityProviderMaterial keeps a lab IdP signing identity stable
// across process restarts. It publishes one complete certificate/key pair to an
// owner-only file. An existing invalid, expired, or wrongly named identity fails
// closed: rotating pinned SAML trust must be an explicit lab operator action.
func LoadOrCreateIdentityProviderMaterial(path, commonName string) (stdcrypto.PrivateKey, *x509.Certificate, error) {
	if path == "" || commonName == "" {
		return nil, nil, errors.New("samltest: identity file and common name are required")
	}
	raw, err := secretfile.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := createIdentityProviderMaterial(path, commonName); err != nil {
			return nil, nil, err
		}
		raw, err = secretfile.Load(path)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("samltest: load lab IdP identity: %w", err)
	}
	defer wipe(raw)
	pair, err := tls.X509KeyPair(raw, raw)
	if err != nil || len(pair.Certificate) != 1 {
		return nil, nil, errors.New("samltest: malformed lab IdP certificate/key pair")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("samltest: parse lab IdP certificate: %w", err)
	}
	if cert.Subject.CommonName != commonName {
		return nil, nil, errors.New("samltest: lab IdP identity belongs to another actor")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, nil, errors.New("samltest: lab IdP certificate is outside its validity window; rotate and repin explicitly")
	}
	return pair.PrivateKey, cert, nil
}

func createIdentityProviderMaterial(path, commonName string) error {
	key, cert, err := newIdentityProviderMaterial(commonName, 30*24*time.Hour)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer wipe(der)
	raw := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
	defer wipe(raw)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("samltest: create identity directory: %w", err)
	}
	if err := secretfile.SecurePrivateDirectory(dir); err != nil {
		return fmt.Errorf("samltest: protect identity directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".saml-idp-*.pem")
	if err != nil {
		return fmt.Errorf("samltest: stage identity: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer func() { _ = tmp.Close() }()
	if err := secretfile.SecurePrivateFile(tmp.Name()); err != nil {
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Link only after the staged inode is complete. A concurrent first start
	// keeps the winner's identity instead of rotating the trust anchor.
	if err := os.Link(tmp.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("samltest: publish identity: %w", err)
	}
	directory, err := os.Open(dir) // #nosec G304 -- operator-selected private identity directory, secured above
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("samltest: sync identity directory: %w", err)
	}
	return nil
}

func wipe(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
	runtime.KeepAlive(raw)
}
