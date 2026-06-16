package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// This file adds the *served* X.509 revocation signing primitives inside the AN-3
// crypto boundary (EXC-REVOKE-01): producing a signed OCSP response and a signed
// CRL for the served issuing CA whose private key lives in the out-of-process
// signer (AN-4). Unlike internal/crypto/ca's in-process Authority/CA — which holds
// a locked key and is the reference/library path — these functions take a
// DigestSigner (a *signing.RemoteSigner for the served CA) and sign through it, so
// the CA private key never enters the control plane's address space: only the
// digest crosses the boundary, exactly as SignLeafFromCSRWithProfile already does
// for leaves. Callers outside the boundary pass and receive only DER bytes,
// strings, ints, and times — never crypto/* or x/crypto/ocsp types.

// OCSP certificate-status values (RFC 6960), re-exported so the served responder
// names a status without importing x/crypto/ocsp (which is crypto and must stay
// inside this boundary, CRYPTO-002).
const (
	OCSPGood    = "good"
	OCSPRevoked = "revoked"
	OCSPUnknown = "unknown"
)

// ErrMalformedOCSPRequest marks OCSP request DER that cannot be parsed into a
// usable RFC 6960 request. HTTP callers translate only this typed client fault to
// 400; signer/store failures must remain server-side errors.
var ErrMalformedOCSPRequest = errors.New("crypto: malformed OCSP request")

// RevokedSerial is a revoked certificate for a CRL: its hex serial, when it was
// revoked, and the RFC 5280 reason code. It is the crypto-free input the served
// CRL generator passes across the boundary.
type RevokedSerial struct {
	Serial    string
	RevokedAt time.Time
	Reason    int
}

// OCSPStatusInfo is the crypto-free result of parsing an OCSP response, returned
// by ParseOCSPResponse so the served path / tests can assert a response's status
// without importing the OCSP wire types.
type OCSPStatusInfo struct {
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

// SignOCSPResponse builds and signs an RFC 6960 OCSP response for serialHex with
// the given status and validity window (and, when revoked, the revocation time and
// reason), using the CA in caCertDER as both issuer and responder (direct signing).
// The signature is produced by caSigner — the CA key in the out-of-process signer
// (AN-4) — so this control-plane code never materializes the CA private key. The
// response is returned as DER.
func SignOCSPResponse(caCertDER []byte, caSigner DigestSigner, status, serialHex string, thisUpdate, nextUpdate, revokedAt time.Time, reason int) ([]byte, error) {
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CA cert: %w", err)
	}
	serial, ok := new(big.Int).SetString(serialHex, 16)
	if !ok {
		return nil, fmt.Errorf("crypto: invalid serial %q", serialHex)
	}
	adapter, err := newX509Signer(caSigner)
	if err != nil {
		return nil, err
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
	der, err := ocsp.CreateResponse(caCert, caCert, tmpl, adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign OCSP response: %w", err)
	}
	return der, nil
}

// CreateCRL builds and signs an RFC 5280 CRL listing the revoked serials, numbered
// number and valid for [thisUpdate, nextUpdate], issued by the CA in caCertDER and
// signed by caSigner (the CA key in the out-of-process signer, AN-4). Returns the
// CRL in DER.
func CreateCRL(caCertDER []byte, caSigner DigestSigner, revoked []RevokedSerial, number int64, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CA cert: %w", err)
	}
	adapter, err := newX509Signer(caSigner)
	if err != nil {
		return nil, err
	}
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, r := range revoked {
		serial, ok := new(big.Int).SetString(r.Serial, 16)
		if !ok {
			return nil, fmt.Errorf("crypto: invalid revoked serial %q", r.Serial)
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
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign CRL: %w", err)
	}
	return der, nil
}

// ParseOCSPRequestSerial reads the queried certificate serial (hex) from an OCSP
// request (DER), so the served responder can resolve the serial's revocation
// status without importing the OCSP wire types.
func ParseOCSPRequestSerial(reqDER []byte) (string, error) {
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformedOCSPRequest, err)
	}
	if req.SerialNumber == nil {
		return "", fmt.Errorf("%w: missing serial", ErrMalformedOCSPRequest)
	}
	return req.SerialNumber.Text(16), nil
}

// BuildOCSPRequest builds an OCSP request (DER) for a leaf certificate under its
// issuer, both given as DER. It is a helper for clients and tests.
func BuildOCSPRequest(leafDER, issuerDER []byte) ([]byte, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse leaf: %w", err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse issuer: %w", err)
	}
	return ocsp.CreateRequest(leaf, issuer, nil)
}

// BuildOCSPRequestForSerial builds an OCSP request (DER) querying a specific
// serial (hex) under the issuer in issuerDER. It is the variant a caller uses when
// it knows the serial it recorded but does not hold the leaf certificate (e.g. the
// served path records a serial in ca_issued_certs and later checks its status).
// The request carries the issuer's name/key hashes and that exact serial, which is
// all an RFC 6960 responder reads.
func BuildOCSPRequestForSerial(issuerDER []byte, serialHex string) ([]byte, error) {
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse issuer: %w", err)
	}
	serial, ok := new(big.Int).SetString(serialHex, 16)
	if !ok {
		return nil, fmt.Errorf("crypto: invalid serial %q", serialHex)
	}
	// ocsp.CreateRequest reads only cert.SerialNumber and the issuer's name/key, so
	// a template carrying the target serial suffices to encode the query.
	return ocsp.CreateRequest(&x509.Certificate{SerialNumber: serial}, issuer, nil)
}

// ParseOCSPResponse parses and VERIFIES an OCSP response (DER) against its issuer
// (DER), returning the crypto-free status. A response whose signature does not
// verify against the issuer is rejected — the boundary helper a relying party (or
// the acceptance test) uses to confirm the served responder's signature is sound.
func ParseOCSPResponse(respDER, issuerDER []byte) (OCSPStatusInfo, error) {
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return OCSPStatusInfo{}, fmt.Errorf("crypto: parse issuer: %w", err)
	}
	resp, err := ocsp.ParseResponse(respDER, issuer)
	if err != nil {
		return OCSPStatusInfo{}, fmt.Errorf("crypto: parse OCSP response: %w", err)
	}
	return OCSPStatusInfo{
		Status:     ocspStatusName(resp.Status),
		Serial:     resp.SerialNumber.Text(16),
		ThisUpdate: resp.ThisUpdate,
		NextUpdate: resp.NextUpdate,
		RevokedAt:  resp.RevokedAt,
		Reason:     resp.RevocationReason,
	}, nil
}

// ParseCRL parses and VERIFIES a CRL (DER) against its issuer (DER), returning its
// number, validity, and revoked serials. A CRL whose signature does not verify
// against the issuer is rejected, so the acceptance test confirms the served CRL's
// signature is sound, not merely that it is well-formed.
func ParseCRL(crlDER, issuerDER []byte) (CRLInfo, error) {
	rl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return CRLInfo{}, fmt.Errorf("crypto: parse CRL: %w", err)
	}
	if len(issuerDER) > 0 {
		issuer, err := x509.ParseCertificate(issuerDER)
		if err != nil {
			return CRLInfo{}, fmt.Errorf("crypto: parse issuer: %w", err)
		}
		if err := rl.CheckSignatureFrom(issuer); err != nil {
			return CRLInfo{}, fmt.Errorf("crypto: CRL signature: %w", err)
		}
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
