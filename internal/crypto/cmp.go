package crypto

// CMP (RFC 4210 / CMPv3) message handling for the p10cr enrollment flow, kept inside the
// AN-3 boundary. A CMP PKIMessage is {header, body, protection, extraCerts}. We implement
// the PKCS#10-carrying request body (p10cr, [4]) with signature-based PKIProtection over
// the ProtectedPart ::= SEQUENCE { header, body }, and the certification response (cp,
// [3]) carrying the issued certificate in cleartext (CMP responses are signed, not
// encrypted). This reuses the existing CSR path; only the message envelope is new ASN.1.
//
// Self-consistent by construction (client and server share these structures); RFC-exact
// interop (the EJBCA/OpenSSL `cmp` differential) is a CI-backstop, like SCEP's libest diff.

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

const (
	cmpPvno2021 = 3 // cmp2021(3)

	cmpBodyTagP10cr = 4 // PKIBody p10cr [4] CertificationRequest
	cmpBodyTagCP    = 3 // PKIBody cp    [3] CertRepMessage

	cmpStatusAccepted  = 0 // PKIStatus accepted(0)
	cmpStatusRejection = 2
)

var (
	oidSigRSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSigECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// cmpHeader is the subset of PKIHeader (RFC 4210 §5.1.1) we populate. The
// explicit context tags follow the ASN.1 module exactly: messageTime [0],
// protectionAlg [1], senderKID [2], transactionID [4], senderNonce [5],
// recipNonce [6], generalInfo [8]. messageTime, senderKID and generalInfo were
// previously omitted (INTEROP-006); messageTime is REQUIRED-in-practice by
// stock CMP servers (EJBCA/OpenSSL) and senderKID/generalInfo (the implicit-
// confirm hint) are populated so the header is RFC-shaped, not a minimal stub.
type cmpHeader struct {
	Pvno          int
	Sender        asn1.RawValue            // GeneralName
	Recipient     asn1.RawValue            // GeneralName
	MessageTime   time.Time                `asn1:"optional,explicit,tag:0,generalized"`
	ProtectionAlg pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SenderKID     []byte                   `asn1:"optional,explicit,tag:2"`
	TransactionID []byte                   `asn1:"optional,explicit,tag:4"`
	SenderNonce   []byte                   `asn1:"optional,explicit,tag:5"`
	RecipNonce    []byte                   `asn1:"optional,explicit,tag:6"`
	GeneralInfo   []cmpInfoTypeAndValue    `asn1:"optional,explicit,tag:8"`
}

// cmpInfoTypeAndValue is InfoTypeAndValue (RFC 4210 §5.3.19), the element type of
// generalInfo. We carry id-it-implicitConfirm to advertise implicit confirmation,
// the common interop hint.
type cmpInfoTypeAndValue struct {
	InfoType  asn1.ObjectIdentifier
	InfoValue asn1.RawValue `asn1:"optional"`
}

// id-it-implicitConfirm (RFC 4210 §5.3.19.13): {id-it 13}.
var oidITImplicitConfirm = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13}

// cmpMessage is PKIMessage.
type cmpMessage struct {
	Header     cmpHeader
	Body       asn1.RawValue   // PKIBody CHOICE ([4] p10cr or [3] cp)
	Protection asn1.BitString  `asn1:"optional,explicit,tag:0"`
	ExtraCerts []asn1.RawValue `asn1:"optional,explicit,tag:1"`
}

// cmpProtectedPart is what the protection signature covers.
type cmpProtectedPart struct {
	Header cmpHeader
	Body   asn1.RawValue
}

// --- response (cp) structures ----------------------------------------------

type cmpStatusInfo struct {
	Status       int
	StatusString []asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.BitString  `asn1:"optional"`
}

type cmpCertifiedKeyPair struct {
	CertOrEncCert asn1.RawValue // CertOrEncCert CHOICE: certificate [0] CMPCertificate.
}

type cmpCertResponse struct {
	CertReqID        int
	Status           cmpStatusInfo
	CertifiedKeyPair cmpCertifiedKeyPair `asn1:"optional"`
}

type cmpCertRepMessage struct {
	Response []cmpCertResponse
}

// CMPRequest is a parsed, protection-verified CMP p10cr request.
type CMPRequest struct {
	Pvno          int
	CSRDER        []byte
	TransactionID []byte
	SenderNonce   []byte
}

// BuildCMPRequest builds a signature-protected CMP p10cr PKIMessage carrying csrDER,
// protected by the client's key and carrying the client cert in extraCerts. Used by CMP
// clients and tests.
func BuildCMPRequest(csrDER, signerCertDER, signerKeyPKCS8, transactionID, senderNonce []byte) ([]byte, error) {
	signerCert, err := x509.ParseCertificate(signerCertDER)
	if err != nil {
		return nil, fmt.Errorf("cmp: parse signer cert: %w", err)
	}
	sender, err := generalNameDirectory(signerCert.Subject)
	if err != nil {
		return nil, err
	}
	body := choiceRaw(cmpBodyTagP10cr, csrDER)

	alg, err := protectionAlgFor(signerKeyPKCS8)
	if err != nil {
		return nil, err
	}
	header := cmpHeader{
		Pvno:          cmpPvno2021,
		Sender:        sender,
		Recipient:     sender,
		MessageTime:   time.Now().UTC(),
		ProtectionAlg: alg,
		SenderKID:     skiOf(signerCert),
		TransactionID: transactionID,
		SenderNonce:   senderNonce,
		GeneralInfo:   []cmpInfoTypeAndValue{{InfoType: oidITImplicitConfirm}},
	}
	prot, err := signProtectedPart(header, body, signerKeyPKCS8)
	if err != nil {
		return nil, err
	}
	msg := cmpMessage{
		Header:     header,
		Body:       body,
		Protection: prot,
		ExtraCerts: []asn1.RawValue{rawCert(signerCertDER)},
	}
	return asn1.Marshal(msg)
}

// ParseCMPRequest parses a CMP p10cr PKIMessage, verifies its signature protection against
// the certificate in extraCerts, and returns the carried PKCS#10. Fails closed on any
// malformed, unprotected, or unverifiable input — the CMP parser fuzz target.
func ParseCMPRequest(der []byte) (*CMPRequest, error) {
	var msg cmpMessage
	if _, err := asn1.Unmarshal(der, &msg); err != nil {
		return nil, fmt.Errorf("cmp: parse PKIMessage: %w", err)
	}
	if msg.Body.Class != asn1.ClassContextSpecific || msg.Body.Tag != cmpBodyTagP10cr {
		return nil, fmt.Errorf("cmp: not a p10cr body (tag %d)", msg.Body.Tag)
	}
	if len(msg.ExtraCerts) == 0 {
		return nil, errors.New("cmp: no extraCerts to verify protection")
	}
	signerCert, err := x509.ParseCertificate(msg.ExtraCerts[0].FullBytes)
	if err != nil {
		return nil, fmt.Errorf("cmp: parse extraCert: %w", err)
	}
	if err := verifyProtection(msg.Header, msg.Body, msg.Protection, signerCert); err != nil {
		return nil, fmt.Errorf("cmp: verify protection: %w", err)
	}
	csrDER := msg.Body.Bytes
	if err := VerifyCertificateRequest(csrDER); err != nil {
		return nil, fmt.Errorf("cmp: body is not a valid CSR: %w", err)
	}
	return &CMPRequest{Pvno: msg.Header.Pvno, CSRDER: csrDER, TransactionID: msg.Header.TransactionID, SenderNonce: msg.Header.SenderNonce}, nil
}

// BuildCMPResponse builds a signature-protected CMP cp PKIMessage carrying the issued
// certificate (cleartext), echoing the request transaction id, signed by the CA.
func BuildCMPResponse(issuedCertDER, caCertDER, caKeyPKCS8 []byte, req *CMPRequest) ([]byte, error) {
	if req == nil {
		return nil, errors.New("cmp: request is required")
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("cmp: parse CA cert: %w", err)
	}
	sender, err := generalNameDirectory(caCert.Subject)
	if err != nil {
		return nil, err
	}
	rep := cmpCertRepMessage{
		Response: []cmpCertResponse{{
			CertReqID: 0,
			Status:    cmpStatusInfo{Status: cmpStatusAccepted},
			CertifiedKeyPair: cmpCertifiedKeyPair{
				CertOrEncCert: choiceRaw(0, issuedCertDER),
			},
		}},
	}
	repDER, err := asn1.Marshal(rep)
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal CertRepMessage: %w", err)
	}
	body := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: cmpBodyTagCP, IsCompound: true, Bytes: repDER}

	alg, err := protectionAlgFor(caKeyPKCS8)
	if err != nil {
		return nil, err
	}
	pvno := req.Pvno
	if pvno == 0 {
		pvno = cmpPvno2021
	}
	header := cmpHeader{
		Pvno:          pvno,
		Sender:        sender,
		Recipient:     sender,
		MessageTime:   time.Now().UTC(),
		ProtectionAlg: alg,
		SenderKID:     skiOf(caCert),
		TransactionID: req.TransactionID,
		SenderNonce:   req.SenderNonce,
		RecipNonce:    req.SenderNonce,
		GeneralInfo:   []cmpInfoTypeAndValue{{InfoType: oidITImplicitConfirm}},
	}
	prot, err := signProtectedPart(header, body, caKeyPKCS8)
	if err != nil {
		return nil, err
	}
	msg := cmpMessage{Header: header, Body: body, Protection: prot, ExtraCerts: []asn1.RawValue{rawCert(caCertDER)}}
	return asn1.Marshal(msg)
}

// ParseCMPResponse parses a CMP cp PKIMessage, checks the status is accepted, and returns
// the issued certificate DER.
func ParseCMPResponse(der []byte) ([]byte, error) {
	var msg cmpMessage
	if _, err := asn1.Unmarshal(der, &msg); err != nil {
		return nil, fmt.Errorf("cmp: parse response: %w", err)
	}
	if msg.Body.Class != asn1.ClassContextSpecific || msg.Body.Tag != cmpBodyTagCP {
		return nil, fmt.Errorf("cmp: not a cp body (tag %d)", msg.Body.Tag)
	}
	var rep cmpCertRepMessage
	if _, err := asn1.Unmarshal(msg.Body.Bytes, &rep); err != nil {
		return nil, fmt.Errorf("cmp: parse CertRepMessage: %w", err)
	}
	if len(rep.Response) == 0 {
		return nil, errors.New("cmp: empty CertRepMessage")
	}
	r := rep.Response[0]
	if r.Status.Status != cmpStatusAccepted {
		return nil, fmt.Errorf("cmp: request rejected (status %d)", r.Status.Status)
	}
	cert := r.CertifiedKeyPair.CertOrEncCert
	if cert.Class != asn1.ClassContextSpecific || cert.Tag != 0 {
		return nil, fmt.Errorf("cmp: response carried unsupported CertOrEncCert choice tag %d", cert.Tag)
	}
	certDER := cert.Bytes
	if len(certDER) == 0 {
		return nil, errors.New("cmp: response carried no certificate")
	}
	return certDER, nil
}

// --- helpers ----------------------------------------------------------------

func choiceRaw(tag int, inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
}

func rawCert(der []byte) asn1.RawValue {
	return asn1.RawValue{FullBytes: der}
}

// skiOf returns the certificate's subjectKeyIdentifier for the CMP senderKID. If
// the certificate carries an SKI extension it is used directly; otherwise the
// SHA-256-truncated key identifier (RFC 7093 method) is derived from the public
// key so senderKID is always populated. Returns nil only if the public key cannot
// be marshalled (the caller then omits the optional field).
func skiOf(cert *x509.Certificate) []byte {
	if len(cert.SubjectKeyId) > 0 {
		return cert.SubjectKeyId
	}
	pkDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(pkDER)
	return sum[:20]
}

func generalNameDirectory(name pkix.Name) (asn1.RawValue, error) {
	rdn := name.ToRDNSequence()
	inner, err := asn1.Marshal(rdn)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("cmp: encode GeneralName: %w", err)
	}
	// GeneralName directoryName [4] EXPLICIT Name.
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: inner}, nil
}

func protectionAlgFor(keyPKCS8 []byte) (pkix.AlgorithmIdentifier, error) {
	key, err := x509.ParsePKCS8PrivateKey(keyPKCS8)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, fmt.Errorf("cmp: parse key: %w", err)
	}
	switch key.(type) {
	case *rsa.PrivateKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidSigRSASHA256}, nil
	case *ecdsa.PrivateKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidSigECDSASHA256}, nil
	default:
		return pkix.AlgorithmIdentifier{}, errors.New("cmp: unsupported protection key type")
	}
}

func signProtectedPart(header cmpHeader, body asn1.RawValue, keyPKCS8 []byte) (asn1.BitString, error) {
	ppDER, err := asn1.Marshal(cmpProtectedPart{Header: header, Body: body})
	if err != nil {
		return asn1.BitString{}, fmt.Errorf("cmp: marshal ProtectedPart: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyPKCS8)
	if err != nil {
		return asn1.BitString{}, fmt.Errorf("cmp: parse key: %w", err)
	}
	signer, ok := key.(stdcrypto.Signer)
	if !ok {
		return asn1.BitString{}, errors.New("cmp: key is not a signer")
	}
	h := sha256.Sum256(ppDER)
	sig, err := signer.Sign(rand.Reader, h[:], stdcrypto.SHA256)
	if err != nil {
		return asn1.BitString{}, fmt.Errorf("cmp: sign ProtectedPart: %w", err)
	}
	return asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}, nil
}

func verifyProtection(header cmpHeader, body asn1.RawValue, prot asn1.BitString, signerCert *x509.Certificate) error {
	ppDER, err := asn1.Marshal(cmpProtectedPart{Header: header, Body: body})
	if err != nil {
		return fmt.Errorf("cmp: re-marshal ProtectedPart: %w", err)
	}
	h := sha256.Sum256(ppDER)
	switch pk := signerCert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pk, stdcrypto.SHA256, h[:], prot.Bytes)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pk, h[:], prot.Bytes) {
			return errors.New("cmp: ECDSA protection signature invalid")
		}
		return nil
	default:
		return errors.New("cmp: unsupported protection public key")
	}
}
