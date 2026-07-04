// SPDX-License-Identifier: MPL-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// This file adds X.509 revocation primitives (F47) inside the AN-3 crypto
// boundary: signing OCSP responses and CRLs with the CA's key, and parsing OCSP
// requests/responses and CRLs into crypto-free results. Callers (the revocation
// service) pass and receive only strings, ints, and times — never crypto/* or
// x/crypto/ocsp types — so the boundary holds all the cryptography.

// OCSP certificate-status values (RFC 6960).
const (
	OCSPGood    = "good"
	OCSPRevoked = "revoked"
	OCSPUnknown = "unknown"
)

// RevokedSerial is a revoked certificate for a CRL: its hex serial, when it was
// revoked, and the RFC 5280 reason code.
type RevokedSerial struct {
	Serial    string
	RevokedAt time.Time
	Reason    int
}

// OCSPStatus is the crypto-free result of parsing an OCSP response.
type OCSPStatus struct {
	Status     string
	Serial     string
	ThisUpdate time.Time
	NextUpdate time.Time
	RevokedAt  time.Time
	Reason     int
}

// CRLInfo is the crypto-free result of parsing a CRL.
type CRLInfo struct {
	Number         int64
	ThisUpdate     time.Time
	NextUpdate     time.Time
	RevokedSerials []string
}

// SignOCSP signs an OCSP response for serialHex with the given status, validity
// window, and (when revoked) revocation time and reason, using this CA as both
// issuer and responder (direct signing).
func (c *CA) SignOCSP(status, serialHex string, thisUpdate, nextUpdate, revokedAt time.Time, reason int) ([]byte, error) {
	serial, ok := new(big.Int).SetString(serialHex, 16)
	if !ok {
		return nil, fmt.Errorf("ca: invalid serial %q", serialHex)
	}
	tmpl := ocsp.Response{
		SerialNumber: serial,
		ThisUpdate:   thisUpdate.UTC(),
		NextUpdate:   nextUpdate.UTC(),
		Status:       ocspStatusCode(status),
	}
	if status == OCSPRevoked {
		tmpl.RevokedAt = revokedAt.UTC()
		tmpl.RevocationReason = reason
	}
	var out []byte
	if err := c.key.sign(func(priv *ecdsa.PrivateKey) error {
		var e error
		out, e = ocsp.CreateResponse(c.cert, c.cert, tmpl, priv)
		return e
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateCRL builds and signs a CRL listing the revoked serials, numbered number
// and valid for [thisUpdate, nextUpdate]. Returns the CRL in DER.
func (c *CA) CreateCRL(revoked []RevokedSerial, number int64, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, r := range revoked {
		serial, ok := new(big.Int).SetString(r.Serial, 16)
		if !ok {
			return nil, fmt.Errorf("ca: invalid revoked serial %q", r.Serial)
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: r.RevokedAt.UTC(),
			ReasonCode:     r.Reason,
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                thisUpdate.UTC(),
		NextUpdate:                nextUpdate.UTC(),
		RevokedCertificateEntries: entries,
	}
	var out []byte
	if err := c.key.sign(func(priv *ecdsa.PrivateKey) error {
		var e error
		out, e = x509.CreateRevocationList(rand.Reader, tmpl, c.cert, priv)
		return e
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// BuildOCSPRequest builds an OCSP request (DER) for a leaf certificate under its
// issuer, both given as DER. It is a helper for clients and tests.
func BuildOCSPRequest(leafDER, issuerDER []byte) ([]byte, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse leaf: %w", err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse issuer: %w", err)
	}
	return ocsp.CreateRequest(leaf, issuer, nil)
}

// ParseOCSPRequestSerial reads the queried certificate serial (hex) from an OCSP
// request (DER).
func ParseOCSPRequestSerial(reqDER []byte) (string, error) {
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return "", fmt.Errorf("ca: parse ocsp request: %w", err)
	}
	return req.SerialNumber.Text(16), nil
}

// ParseOCSPResponse parses and verifies an OCSP response (DER) against its issuer
// (DER), returning the crypto-free status.
func ParseOCSPResponse(respDER, issuerDER []byte) (OCSPStatus, error) {
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return OCSPStatus{}, fmt.Errorf("ca: parse issuer: %w", err)
	}
	resp, err := ocsp.ParseResponse(respDER, issuer)
	if err != nil {
		return OCSPStatus{}, fmt.Errorf("ca: parse ocsp response: %w", err)
	}
	return OCSPStatus{
		Status:     ocspStatusName(resp.Status),
		Serial:     resp.SerialNumber.Text(16),
		ThisUpdate: resp.ThisUpdate,
		NextUpdate: resp.NextUpdate,
		RevokedAt:  resp.RevokedAt,
		Reason:     resp.RevocationReason,
	}, nil
}

// ParseCRL parses a CRL (DER) into its number, validity, and revoked serials.
func ParseCRL(crlDER []byte) (CRLInfo, error) {
	rl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return CRLInfo{}, fmt.Errorf("ca: parse crl: %w", err)
	}
	info := CRLInfo{ThisUpdate: rl.ThisUpdate, NextUpdate: rl.NextUpdate}
	if rl.Number != nil {
		info.Number = rl.Number.Int64()
	}
	for _, e := range rl.RevokedCertificateEntries {
		info.RevokedSerials = append(info.RevokedSerials, e.SerialNumber.Text(16))
	}
	return info, nil
}

func ocspStatusCode(status string) int {
	switch status {
	case OCSPGood:
		return ocsp.Good
	case OCSPRevoked:
		return ocsp.Revoked
	default:
		return ocsp.Unknown
	}
}

func ocspStatusName(code int) string {
	switch code {
	case ocsp.Good:
		return OCSPGood
	case ocsp.Revoked:
		return OCSPRevoked
	default:
		return OCSPUnknown
	}
}
