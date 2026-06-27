package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
var oidOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// MaxOCSPNonceLength is the accepted nonce payload cap. The CA/B Forum Baseline
// Requirements recommend nonces of at most 32 octets; larger request values are
// rejected instead of echoed into a signed response.
const MaxOCSPNonceLength = 32

// RevocationReason is the RFC 5280 Section 5.3.1 CRL reason name carried by
// API/event payloads. The integer CRL/OCSP wire value is derived from this enum so
// callers cannot smuggle arbitrary raw codes into relying-party evidence.
type RevocationReason string

const (
	RevocationReasonUnspecified          RevocationReason = "unspecified"
	RevocationReasonKeyCompromise        RevocationReason = "keyCompromise"
	RevocationReasonCACompromise         RevocationReason = "caCompromise"
	RevocationReasonAffiliationChanged   RevocationReason = "affiliationChanged"
	RevocationReasonSuperseded           RevocationReason = "superseded"
	RevocationReasonCessationOfOperation RevocationReason = "cessationOfOperation"
	RevocationReasonCertificateHold      RevocationReason = "certificateHold"
	RevocationReasonRemoveFromCRL        RevocationReason = "removeFromCRL"
	RevocationReasonPrivilegeWithdrawn   RevocationReason = "privilegeWithdrawn"
	RevocationReasonAACompromise         RevocationReason = "aaCompromise"
)

// ValidRevocationReasons maps each named RFC 5280 reason to its CRL reason code.
var ValidRevocationReasons = map[RevocationReason]int{
	RevocationReasonUnspecified:          0,
	RevocationReasonKeyCompromise:        1,
	RevocationReasonCACompromise:         2,
	RevocationReasonAffiliationChanged:   3,
	RevocationReasonSuperseded:           4,
	RevocationReasonCessationOfOperation: 5,
	RevocationReasonCertificateHold:      6,
	RevocationReasonRemoveFromCRL:        8,
	RevocationReasonPrivilegeWithdrawn:   9,
	RevocationReasonAACompromise:         10,
}

var revocationReasonsByCode = func() map[int]RevocationReason {
	out := make(map[int]RevocationReason, len(ValidRevocationReasons))
	for reason, code := range ValidRevocationReasons {
		out[code] = reason
	}
	return out
}()

// IsValidRevocationReason reports whether reason is a named RFC 5280 reason.
func IsValidRevocationReason(reason string) bool {
	_, ok := ValidRevocationReasons[RevocationReason(reason)]
	return ok
}

// CRLReasonCode maps a named revocation reason to its RFC 5280 CRL reason code.
// Unknown reasons map to unspecified for display-only callers; mutating code must
// use IsValidRevocationReason or ValidateCRLReasonCode before emitting evidence.
func CRLReasonCode(reason RevocationReason) int {
	if code, ok := ValidRevocationReasons[reason]; ok {
		return code
	}
	return ValidRevocationReasons[RevocationReasonUnspecified]
}

// RevocationReasonFromCRLCode maps an RFC 5280 CRL reason code back to its name.
func RevocationReasonFromCRLCode(code int) (RevocationReason, bool) {
	reason, ok := revocationReasonsByCode[code]
	return reason, ok
}

// ValidCRLReasonCode reports whether code is assigned by RFC 5280 Section 5.3.1.
func ValidCRLReasonCode(code int) bool {
	_, ok := revocationReasonsByCode[code]
	return ok
}

func validateCRLReasonCode(code int) error {
	if ValidCRLReasonCode(code) {
		return nil
	}
	return fmt.Errorf("crypto: invalid RFC 5280 revocation reason code %d", code)
}

// ErrMalformedOCSPRequest marks OCSP request DER that cannot be parsed into a
// usable RFC 6960 request. HTTP callers translate only this typed client fault to
// 400; signer/store failures must remain server-side errors.
var ErrMalformedOCSPRequest = errors.New("crypto: malformed OCSP request")

// ErrOCSPNonceMalformed marks a request nonce extension whose value is empty,
// oversized, or not a DER OCTET STRING.
var ErrOCSPNonceMalformed = errors.New("crypto: OCSP nonce malformed")

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
	Status                     string
	Serial                     string
	ThisUpdate                 time.Time
	NextUpdate                 time.Time
	RevokedAt                  time.Time
	Reason                     int
	ResponderSerial            string
	ResponderSubject           string
	ResponderIsIssuer          bool
	ResponderHasOCSPSigningEKU bool
	ResponderHasOCSPNoCheck    bool
	Nonce                      []byte
	HasNonce                   bool
}

// OCSPResponderInfo is crypto-free metadata about a delegated OCSP responder
// certificate. It lets callers/tests assert the security properties without
// importing x509 outside the crypto boundary.
type OCSPResponderInfo struct {
	Serial            string
	Subject           string
	NotBefore         time.Time
	NotAfter          time.Time
	IsCA              bool
	HasOCSPSigningEKU bool
	HasOCSPNoCheck    bool
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
	return SignOCSPResponseWithNonce(caCertDER, caSigner, status, serialHex, thisUpdate, nextUpdate, revokedAt, reason, nil)
}

// SignOCSPResponseWithNonce is SignOCSPResponse plus an optional RFC 6960 nonce
// response extension. A nil nonce produces the nonce-free base response.
func SignOCSPResponseWithNonce(caCertDER []byte, caSigner DigestSigner, status, serialHex string, thisUpdate, nextUpdate, revokedAt time.Time, reason int, nonce []byte) ([]byte, error) {
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
	extra, err := ocspNonceExtensions(nonce)
	if err != nil {
		return nil, err
	}
	tmpl := ocsp.Response{
		SerialNumber:    serial,
		ThisUpdate:      thisUpdate.UTC(),
		NextUpdate:      nextUpdate.UTC(),
		Status:          ocspStatusCode(status),
		ExtraExtensions: extra,
	}
	if status == OCSPRevoked {
		if err := validateCRLReasonCode(reason); err != nil {
			return nil, err
		}
		tmpl.RevokedAt = revokedAt.UTC()
		tmpl.RevocationReason = reason
	}
	der, err := ocsp.CreateResponse(caCert, caCert, tmpl, adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign OCSP response: %w", err)
	}
	return der, nil
}

// CreateOCSPResponderCertificate mints a delegated OCSP responder certificate:
// the CA signs the responder public key, but the resulting cert is limited to
// digitalSignature + OCSPSigning and carries id-pkix-ocsp-nocheck. The CA signing
// operation still goes through DigestSigner, so in production it crosses the
// signer process boundary (AN-4).
func CreateOCSPResponderCertificate(caCertDER []byte, caSigner DigestSigner, responderSigner DigestSigner, commonName string, notBefore, notAfter time.Time) ([]byte, error) {
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CA cert: %w", err)
	}
	caAdapter, err := newX509Signer(caSigner)
	if err != nil {
		return nil, err
	}
	if responderSigner == nil {
		return nil, errors.New("crypto: OCSP responder signer is required")
	}
	responderAdapter, err := newX509Signer(responderSigner)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore.UTC(),
		NotAfter:              notAfter.UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{{
			Id:    oidOCSPNoCheck,
			Value: []byte{0x05, 0x00}, // DER NULL, the RFC 6960 ocsp-nocheck value.
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, responderAdapter.Public(), caAdapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: create OCSP responder cert: %w", err)
	}
	return der, nil
}

// SignDelegatedOCSPResponse signs an OCSP response with a delegated responder
// certificate that chains to caCertDER. The response embeds the responder cert, so
// a verifier that trusts the issuer can verify the status without holding the
// responder cert out of band.
func SignDelegatedOCSPResponse(caCertDER, responderCertDER []byte, responderSigner DigestSigner, status, serialHex string, thisUpdate, nextUpdate, revokedAt time.Time, reason int) ([]byte, error) {
	return SignDelegatedOCSPResponseWithNonce(caCertDER, responderCertDER, responderSigner, status, serialHex, thisUpdate, nextUpdate, revokedAt, reason, nil)
}

// SignDelegatedOCSPResponseWithNonce is SignDelegatedOCSPResponse plus an
// optional RFC 6960 nonce response extension. A nil nonce produces the cacheable
// nonce-free base response.
func SignDelegatedOCSPResponseWithNonce(caCertDER, responderCertDER []byte, responderSigner DigestSigner, status, serialHex string, thisUpdate, nextUpdate, revokedAt time.Time, reason int, nonce []byte) ([]byte, error) {
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CA cert: %w", err)
	}
	responderCert, err := x509.ParseCertificate(responderCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse OCSP responder cert: %w", err)
	}
	if err := validateOCSPResponderCertificate(caCert, responderCert); err != nil {
		return nil, err
	}
	serial, ok := new(big.Int).SetString(serialHex, 16)
	if !ok {
		return nil, fmt.Errorf("crypto: invalid serial %q", serialHex)
	}
	adapter, err := newX509Signer(responderSigner)
	if err != nil {
		return nil, err
	}
	extra, err := ocspNonceExtensions(nonce)
	if err != nil {
		return nil, err
	}
	tmpl := ocsp.Response{
		SerialNumber:    serial,
		ThisUpdate:      thisUpdate.UTC(),
		NextUpdate:      nextUpdate.UTC(),
		Status:          ocspStatusCode(status),
		Certificate:     responderCert,
		ExtraExtensions: extra,
	}
	if status == OCSPRevoked {
		if err := validateCRLReasonCode(reason); err != nil {
			return nil, err
		}
		tmpl.RevokedAt = revokedAt.UTC()
		tmpl.RevocationReason = reason
	}
	der, err := ocsp.CreateResponse(caCert, responderCert, tmpl, adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign delegated OCSP response: %w", err)
	}
	return der, nil
}

// InspectOCSPResponderCertificate verifies responderDER chains to caCertDER and
// returns the delegated-responder properties callers are allowed to depend on.
func InspectOCSPResponderCertificate(caCertDER, responderDER []byte) (OCSPResponderInfo, error) {
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return OCSPResponderInfo{}, fmt.Errorf("crypto: parse CA cert: %w", err)
	}
	responder, err := x509.ParseCertificate(responderDER)
	if err != nil {
		return OCSPResponderInfo{}, fmt.Errorf("crypto: parse OCSP responder cert: %w", err)
	}
	if err := validateOCSPResponderCertificate(caCert, responder); err != nil {
		return OCSPResponderInfo{}, err
	}
	return ocspResponderInfo(responder), nil
}

// OCSPResponderCertificateMatchesSigner reports whether responderDER contains
// the public key for signer. It lets the served path detect a stale projected
// responder certificate after signer restart/key replacement without importing
// x509 outside the crypto boundary.
func OCSPResponderCertificateMatchesSigner(responderDER []byte, signer DigestSigner) (bool, error) {
	responder, err := x509.ParseCertificate(responderDER)
	if err != nil {
		return false, fmt.Errorf("crypto: parse OCSP responder cert: %w", err)
	}
	adapter, err := newX509Signer(signer)
	if err != nil {
		return false, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(adapter.Public())
	if err != nil {
		return false, fmt.Errorf("crypto: marshal signer public key: %w", err)
	}
	return bytes.Equal(pubDER, responder.RawSubjectPublicKeyInfo), nil
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
		if err := validateCRLReasonCode(r.Reason); err != nil {
			return nil, err
		}
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

// ParseOCSPRequestNonce extracts the optional RFC 6960 id-pkix-ocsp-nonce
// extension from an OCSP request. It returns present=false when the extension is
// absent. If present, the nonce must be a non-empty DER OCTET STRING no larger
// than MaxOCSPNonceLength.
func ParseOCSPRequestNonce(reqDER []byte) ([]byte, bool, error) {
	var outer asn1.RawValue
	if rest, err := asn1.Unmarshal(reqDER, &outer); err != nil || len(rest) != 0 {
		return nil, false, fmt.Errorf("%w: %w", ErrMalformedOCSPRequest, err)
	}
	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &tbs); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrMalformedOCSPRequest, err)
	}
	tail := tbs.Bytes
	for len(tail) > 0 {
		var elem asn1.RawValue
		var err error
		tail, err = asn1.Unmarshal(tail, &elem)
		if err != nil {
			return nil, false, fmt.Errorf("%w: %w", ErrMalformedOCSPRequest, err)
		}
		if elem.Class == asn1.ClassContextSpecific && elem.Tag == 2 {
			return parseOCSPNonceExtensions(elem.Bytes)
		}
	}
	return nil, false, nil
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

// BuildOCSPRequestForSerialWithNonce builds an OCSP request for serialHex and,
// when nonce is non-nil, includes the RFC 6960 nonce extension.
func BuildOCSPRequestForSerialWithNonce(issuerDER []byte, serialHex string, nonce []byte) ([]byte, error) {
	base, err := BuildOCSPRequestForSerial(issuerDER, serialHex)
	if err != nil {
		return nil, err
	}
	if nonce == nil {
		return base, nil
	}
	if err := validateOCSPNonce(nonce); err != nil {
		return nil, err
	}
	exts, err := ocspNonceExtensions(nonce)
	if err != nil {
		return nil, err
	}
	extDER, err := asn1.Marshal(exts)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal OCSP nonce extension: %w", err)
	}
	reqExtDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: extDER})
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal OCSP request extensions: %w", err)
	}
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(base, &outer); err != nil {
		return nil, fmt.Errorf("crypto: parse base OCSP request: %w", err)
	}
	var tbs asn1.RawValue
	rest, err := asn1.Unmarshal(outer.Bytes, &tbs)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse base OCSP tbsRequest: %w", err)
	}
	tbs.Bytes = append(append([]byte(nil), tbs.Bytes...), reqExtDER...)
	tbs.FullBytes = nil
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal OCSP tbsRequest: %w", err)
	}
	outer.Bytes = append(append([]byte(nil), tbsDER...), rest...)
	outer.FullBytes = nil
	out, err := asn1.Marshal(outer)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal OCSP request: %w", err)
	}
	return out, nil
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
	responder := issuer
	responderIsIssuer := true
	if resp.Certificate != nil {
		responder = resp.Certificate
		responderIsIssuer = responder.SerialNumber.Cmp(issuer.SerialNumber) == 0 && bytes.Equal(responder.RawSubject, issuer.RawSubject)
	}
	responderInfo := ocspResponderInfo(responder)
	nonce, hasNonce, err := parseOCSPNonceFromParsedExtensions(resp.Extensions)
	if err != nil {
		return OCSPStatusInfo{}, err
	}
	return OCSPStatusInfo{
		Status:                     ocspStatusName(resp.Status),
		Serial:                     resp.SerialNumber.Text(16),
		ThisUpdate:                 resp.ThisUpdate,
		NextUpdate:                 resp.NextUpdate,
		RevokedAt:                  resp.RevokedAt,
		Reason:                     resp.RevocationReason,
		ResponderSerial:            responderInfo.Serial,
		ResponderSubject:           responderInfo.Subject,
		ResponderIsIssuer:          responderIsIssuer,
		ResponderHasOCSPSigningEKU: responderInfo.HasOCSPSigningEKU,
		ResponderHasOCSPNoCheck:    responderInfo.HasOCSPNoCheck,
		Nonce:                      nonce,
		HasNonce:                   hasNonce,
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

func validateOCSPResponderCertificate(caCert, responder *x509.Certificate) error {
	if caCert == nil || responder == nil {
		return errors.New("crypto: CA and OCSP responder certificates are required")
	}
	if err := responder.CheckSignatureFrom(caCert); err != nil {
		return fmt.Errorf("crypto: OCSP responder certificate signature: %w", err)
	}
	info := ocspResponderInfo(responder)
	if info.IsCA {
		return errors.New("crypto: OCSP responder certificate must not be a CA")
	}
	if !info.HasOCSPSigningEKU {
		return errors.New("crypto: OCSP responder certificate missing OCSPSigning EKU")
	}
	if !info.HasOCSPNoCheck {
		return errors.New("crypto: OCSP responder certificate missing ocsp-nocheck")
	}
	return nil
}

func ocspResponderInfo(cert *x509.Certificate) OCSPResponderInfo {
	if cert == nil {
		return OCSPResponderInfo{}
	}
	info := OCSPResponderInfo{
		Serial:    cert.SerialNumber.Text(16),
		Subject:   cert.Subject.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		IsCA:      cert.IsCA,
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			info.HasOCSPSigningEKU = true
			break
		}
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidOCSPNoCheck) {
			info.HasOCSPNoCheck = true
			break
		}
	}
	return info
}

func ocspNonceExtensions(nonce []byte) ([]pkix.Extension, error) {
	if nonce == nil {
		return nil, nil
	}
	if err := validateOCSPNonce(nonce); err != nil {
		return nil, err
	}
	value, err := asn1.Marshal(nonce)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal OCSP nonce: %w", err)
	}
	return []pkix.Extension{{Id: oidOCSPNonce, Value: value}}, nil
}

func parseOCSPNonceExtensions(extBytes []byte) ([]byte, bool, error) {
	var exts []pkix.Extension
	if _, err := asn1.Unmarshal(extBytes, &exts); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrOCSPNonceMalformed, err)
	}
	return parseOCSPNonceFromParsedExtensions(exts)
}

func parseOCSPNonceFromParsedExtensions(exts []pkix.Extension) ([]byte, bool, error) {
	for _, ext := range exts {
		if !ext.Id.Equal(oidOCSPNonce) {
			continue
		}
		var nonce []byte
		if _, err := asn1.Unmarshal(ext.Value, &nonce); err != nil {
			return nil, false, fmt.Errorf("%w: %w", ErrOCSPNonceMalformed, err)
		}
		if err := validateOCSPNonce(nonce); err != nil {
			return nil, false, err
		}
		return nonce, true, nil
	}
	return nil, false, nil
}

func validateOCSPNonce(nonce []byte) error {
	if len(nonce) == 0 || len(nonce) > MaxOCSPNonceLength {
		return ErrOCSPNonceMalformed
	}
	return nil
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
