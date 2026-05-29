// Package certinfo extracts inventory metadata from an X.509 certificate inside
// the AN-3 crypto boundary (a subpackage of internal/crypto, so it alone may
// import crypto/x509). Callers outside the boundary consume only the crypto-free
// Info struct, so the certificate-inventory layer never imports crypto/*.
package certinfo

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Info is the inventory metadata of a certificate.
type Info struct {
	Subject           string
	Issuer            string
	SerialNumber      string // hex
	DNSNames          []string
	IPAddresses       []string
	EmailAddresses    []string
	URIs              []string
	NotBefore         time.Time
	NotAfter          time.Time
	SHA256Fingerprint string // hex of the DER
	KeyAlgorithm      string
	IsCA              bool
}

// Inspect parses a certificate (PEM or DER) and returns its inventory metadata.
func Inspect(raw []byte) (Info, error) {
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return Info{}, fmt.Errorf("certinfo: PEM block is %q, not CERTIFICATE", block.Type)
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Info{}, fmt.Errorf("certinfo: parse certificate: %w", err)
	}
	if cert.SerialNumber == nil {
		return Info{}, errors.New("certinfo: certificate has no serial number")
	}

	sum := sha256.Sum256(cert.Raw)
	info := Info{
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		SerialNumber:      cert.SerialNumber.Text(16),
		DNSNames:          cert.DNSNames,
		EmailAddresses:    cert.EmailAddresses,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		SHA256Fingerprint: hex.EncodeToString(sum[:]),
		KeyAlgorithm:      cert.PublicKeyAlgorithm.String(),
		IsCA:              cert.IsCA,
	}
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	for _, u := range cert.URIs {
		info.URIs = append(info.URIs, u.String())
	}
	return info, nil
}
