// SPDX-License-Identifier: BUSL-1.1

package deviceattesttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

var (
	oidYubicoSerial = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidYubicoPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
)

// TokenAttestationAuthority stands in for a PKCS#11 token vendor's
// attestation hierarchy (A175): a vendor root, a per-device attestation
// certificate under it, and leaves that certify one key the device holds,
// with the serial and PIN/touch policy extensions a YubiKey's PIV
// attestation carries.
type TokenAttestationAuthority struct {
	rootPEM   []byte
	device    *x509.Certificate
	deviceDER []byte
	deviceKey *ecdsa.PrivateKey
	serial    int64
}

// NewTokenAttestationAuthority builds a vendor root and one device
// attestation certificate valid around now.
func NewTokenAttestationAuthority(now time.Time, serial int64) (*TokenAttestationAuthority, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Stand-in Token Vendor Attestation Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	deviceTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: fmt.Sprintf("Stand-in Token Attestation %d", serial)},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	deviceDER, err := x509.CreateCertificate(rand.Reader, deviceTmpl, root, &deviceKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	device, err := x509.ParseCertificate(deviceDER)
	if err != nil {
		return nil, err
	}
	return &TokenAttestationAuthority{rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		device: device, deviceDER: deviceDER, deviceKey: deviceKey, serial: serial}, nil
}

// RootPEM is the vendor root a segment pins.
func (a *TokenAttestationAuthority) RootPEM() []byte { return append([]byte(nil), a.rootPEM...) }

// DeviceDER is the device attestation certificate (the chain's second link).
func (a *TokenAttestationAuthority) DeviceDER() []byte { return append([]byte(nil), a.deviceDER...) }

// AttestCSR returns the chain (leaf first) certifying the CSR's public key.
func (a *TokenAttestationAuthority) AttestCSR(csrDER []byte, now time.Time) ([][]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	leaf, err := a.attest(csr.PublicKey, now)
	if err != nil {
		return nil, err
	}
	return [][]byte{leaf, a.DeviceDER()}, nil
}

// AttestPublicKeyDER returns the attestation leaf for a PKIX public key, the
// way a token module exposes it next to the key.
func (a *TokenAttestationAuthority) AttestPublicKeyDER(spkiDER []byte, now time.Time) ([]byte, error) {
	pub, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return nil, err
	}
	return a.attest(pub, now)
}

func (a *TokenAttestationAuthority) attest(pub any, now time.Time) ([]byte, error) {
	serial, err := asn1.Marshal(a.serial)
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "Stand-in Token Key Attestation"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidYubicoSerial, Value: serial}, {Id: oidYubicoPolicy, Value: []byte{2, 1}}}}
	return x509.CreateCertificate(rand.Reader, leaf, a.device, pub, a.deviceKey)
}

// CertificateSubjectDER returns a certificate's DER subject, which a PKCS#11
// certificate object must carry (CKA_SUBJECT) beside its value.
func CertificateSubjectDER(der []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), cert.RawSubject...), nil
}
