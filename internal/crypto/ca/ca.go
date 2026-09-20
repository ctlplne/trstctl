// SPDX-License-Identifier: BUSL-1.1

// Package ca is the X.509 certificate-issuance authority inside the AN-3 crypto
// boundary (a subpackage of internal/crypto): it turns a PKCS#10 CSR into a
// signed leaf certificate. Callers outside the boundary use the crypto-free
// Issued result, so the CA-plugin layer (internal/ca) never imports crypto/*.
//
// This in-process Authority holds its signing key directly. In production a CA's
// signing key is custodied by the signer process (AN-4); the Authority is the
// reference issuance path the built-in CA uses and the signer-backed CA will
// substitute behind the same interface.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

// Authority is a self-signed X.509 certificate authority. Its signing key is held
// in a locked secret buffer (mlock + MADV_DONTDUMP, AN-8) and reconstructed only
// for the instant of each signature (CRYPTO-005); the full HSM/signer custody is
// EXC-CRYPTO-01.
type Authority struct {
	cert *x509.Certificate
	der  []byte
	key  *lockedKey
}

// Destroy zeroizes and releases the Authority's locked signing key. Idempotent.
func (a *Authority) Destroy() { a.key.destroy() }

// Issued is the crypto-free result of issuing a certificate: the leaf followed by
// the issuing CA certificate, PEM-encoded, plus the leaf's serial and expiry.
type Issued struct {
	CertificatePEM []byte
	Serial         string
	NotAfter       time.Time
}

// NewAuthority creates a CA with a fresh signing key and a self-signed CA
// certificate.
func NewAuthority(commonName string) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             boundarycrypto.IssuanceNotBefore(now),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	locked, err := newLockedKey(key)
	if err != nil {
		return nil, err
	}
	var der []byte
	if err := locked.sign(func(priv *ecdsa.PrivateKey) error {
		var e error
		der, e = x509.CreateCertificate(rand.Reader, tmpl, tmpl, locked.public(), priv)
		return e
	}); err != nil {
		locked.destroy()
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		locked.destroy()
		return nil, err
	}
	return &Authority{cert: cert, der: der, key: locked}, nil
}

// CertificatePEM returns the CA certificate in PEM form.
func (a *Authority) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.der})
}

// IssueFromCSR validates a PKCS#10 CSR and signs a leaf certificate carrying its
// subject, SANs, and public key, valid for ttl. The returned PEM is the leaf
// followed by this CA's certificate (the chain).
func (a *Authority) IssueFromCSR(csrDER []byte, ttl time.Duration) (Issued, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return Issued{}, fmt.Errorf("ca: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return Issued{}, fmt.Errorf("ca: csr signature: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Issued{}, err
	}
	now := time.Now()
	notAfter := now.Add(ttl)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		NotBefore:             boundarycrypto.IssuanceNotBefore(now),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	var leafDER []byte
	if err := a.key.sign(func(priv *ecdsa.PrivateKey) error {
		var e error
		leafDER, e = x509.CreateCertificate(rand.Reader, tmpl, a.cert, csr.PublicKey, priv)
		return e
	}); err != nil {
		return Issued{}, fmt.Errorf("ca: sign certificate: %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	out = append(out, a.CertificatePEM()...)
	return Issued{CertificatePEM: out, Serial: serial.Text(16), NotAfter: notAfter}, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
