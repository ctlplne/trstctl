package crypto

// SCEP (RFC 8894) CMS message handling, kept inside the AN-3 boundary so the protocol
// server (internal/protocols/scep) never touches crypto/* or the CMS library directly.
//
// A SCEP enrollment request (PKIOperation) is a CMS SignedData (the pkiMessage) carrying
// SCEP signed attributes (messageType, transactionID, senderNonce) and encapsulating a
// CMS EnvelopedData (the pkcsPKIEnvelope) that encrypts the PKCS#10 to the RA/CA. So the
// server must DECRYPT — a capability the rest of the boundary doesn't need — which is why
// SCEP needs an RA RSA key here. The reply (CertRep) is the inverse: the issued cert as a
// degenerate certs-only PKCS#7, enveloped to the requester, wrapped in a CA-signed
// SignedData echoing the transaction id and nonces.

import (
	stdcrypto "crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/smallstep/pkcs7"
)

// SCEP messageType values (RFC 8894 §3.2.1.2).
const (
	SCEPMessagePKCSReq    = "19" // initial enrollment
	SCEPMessageRenewalReq = "17" // renewal
	SCEPMessageCertRep    = "3"  // CA response
)

// SCEP pkiStatus values.
const (
	scepStatusSuccess = "0"
	scepStatusFailure = "2"
)

// SCEP signed-attribute OIDs (the VeriSign arc, 2.16.840.1.113733.1.9.x).
var (
	oidSCEPMessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPPKIStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPSenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPRecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidSCEPTransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// SCEPRequest is a parsed, decrypted SCEP enrollment request.
type SCEPRequest struct {
	MessageType   string
	TransactionID string
	SenderNonce   []byte
	CSRDER        []byte            // the decrypted PKCS#10
	signerCert    *x509.Certificate // the requester's (self-signed) cert; the reply is enveloped to it
}

// ParseSCEPRequest parses a SCEP pkiMessage, verifies its CMS self-signature, reads the
// SCEP signed attributes, and decrypts the enclosed pkcsPKIEnvelope with the RA key,
// returning the inner PKCS#10. raCertDER/raKeyPKCS8 are the recipient (RA/CA) cert and its
// RSA private key, used only here. It fails closed on any malformed, unverifiable, or
// non-RSA input — this is the SCEP parser fuzz target.
func ParseSCEPRequest(pkiMessageDER, raCertDER, raKeyPKCS8 []byte) (*SCEPRequest, error) {
	p7, err := pkcs7.Parse(pkiMessageDER)
	if err != nil {
		return nil, fmt.Errorf("scep: parse pkiMessage: %w", err)
	}
	if err := p7.Verify(); err != nil {
		return nil, fmt.Errorf("scep: verify pkiMessage signature: %w", err)
	}

	var messageType string
	if err := p7.UnmarshalSignedAttribute(oidSCEPMessageType, &messageType); err != nil {
		return nil, fmt.Errorf("scep: read messageType: %w", err)
	}
	if messageType != SCEPMessagePKCSReq && messageType != SCEPMessageRenewalReq {
		return nil, fmt.Errorf("scep: unsupported messageType %q", messageType)
	}
	var transactionID string
	if err := p7.UnmarshalSignedAttribute(oidSCEPTransactionID, &transactionID); err != nil {
		return nil, fmt.Errorf("scep: read transactionID: %w", err)
	}
	var senderNonce []byte
	_ = p7.UnmarshalSignedAttribute(oidSCEPSenderNonce, &senderNonce)

	raKey, err := rsaKeyFromPKCS8(raKeyPKCS8)
	if err != nil {
		return nil, err
	}
	raCert, err := x509.ParseCertificate(raCertDER)
	if err != nil {
		return nil, fmt.Errorf("scep: parse RA cert: %w", err)
	}

	env, err := pkcs7.Parse(p7.Content)
	if err != nil {
		return nil, fmt.Errorf("scep: parse pkcsPKIEnvelope: %w", err)
	}
	csrDER, err := env.Decrypt(raCert, raKey)
	if err != nil {
		return nil, fmt.Errorf("scep: decrypt pkcsPKIEnvelope: %w", err)
	}
	if err := VerifyCertificateRequest(csrDER); err != nil {
		return nil, fmt.Errorf("scep: enveloped content is not a valid CSR: %w", err)
	}
	return &SCEPRequest{
		MessageType:   messageType,
		TransactionID: transactionID,
		SenderNonce:   senderNonce,
		CSRDER:        csrDER,
		signerCert:    p7.GetOnlySigner(),
	}, nil
}

// BuildSCEPSuccess builds a SCEP CertRep pkiMessage carrying the issued certificate: a
// CA-signed CMS SignedData whose encrypted content (enveloped to the original requester)
// is the issued cert as a degenerate certs-only PKCS#7, echoing the request's transaction
// id and (as recipientNonce) its sender nonce. caCertDER/caKeyPKCS8 sign the reply.
func BuildSCEPSuccess(issuedCertDER, caCertDER, caKeyPKCS8 []byte, req *SCEPRequest) ([]byte, error) {
	if req == nil || req.signerCert == nil {
		return nil, errors.New("scep: cannot build a reply without the requester certificate")
	}
	caKey, err := rsaKeyFromPKCS8(caKeyPKCS8)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("scep: parse CA cert: %w", err)
	}

	degenerate, err := pkcs7.DegenerateCertificate(issuedCertDER)
	if err != nil {
		return nil, fmt.Errorf("scep: wrap issued cert: %w", err)
	}
	enveloped, err := pkcs7.Encrypt(degenerate, []*x509.Certificate{req.signerCert})
	if err != nil {
		return nil, fmt.Errorf("scep: envelope reply to requester: %w", err)
	}

	sd, err := pkcs7.NewSignedData(enveloped)
	if err != nil {
		return nil, fmt.Errorf("scep: new reply SignedData: %w", err)
	}
	caNonce, err := RandomBytes(16)
	if err != nil {
		return nil, err
	}
	attrs := []pkcs7.Attribute{
		{Type: oidSCEPMessageType, Value: SCEPMessageCertRep},
		{Type: oidSCEPPKIStatus, Value: scepStatusSuccess},
		{Type: oidSCEPTransactionID, Value: req.TransactionID},
		{Type: oidSCEPSenderNonce, Value: caNonce},
		{Type: oidSCEPRecipientNonce, Value: req.SenderNonce},
	}
	if err := sd.AddSigner(caCert, caKey, pkcs7.SignerInfoConfig{ExtraSignedAttributes: attrs}); err != nil {
		return nil, fmt.Errorf("scep: sign reply: %w", err)
	}
	return sd.Finish()
}

// BuildSCEPRequest builds a client SCEP PKCSReq pkiMessage: it envelopes csrDER to the RA
// (raCertDER) and signs the result with the client's self-signed cert, carrying the SCEP
// messageType/transactionID/senderNonce attributes. Used by enrolling clients and tests.
func BuildSCEPRequest(csrDER, clientCertDER, clientKeyPKCS8, raCertDER []byte, transactionID string) ([]byte, error) {
	raCert, err := x509.ParseCertificate(raCertDER)
	if err != nil {
		return nil, fmt.Errorf("scep: parse RA cert: %w", err)
	}
	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		return nil, fmt.Errorf("scep: parse client cert: %w", err)
	}
	clientKey, err := rsaKeyFromPKCS8(clientKeyPKCS8)
	if err != nil {
		return nil, err
	}
	enveloped, err := pkcs7.Encrypt(csrDER, []*x509.Certificate{raCert})
	if err != nil {
		return nil, fmt.Errorf("scep: envelope CSR to RA: %w", err)
	}
	sd, err := pkcs7.NewSignedData(enveloped)
	if err != nil {
		return nil, fmt.Errorf("scep: new request SignedData: %w", err)
	}
	nonce, err := RandomBytes(16)
	if err != nil {
		return nil, err
	}
	attrs := []pkcs7.Attribute{
		{Type: oidSCEPMessageType, Value: SCEPMessagePKCSReq},
		{Type: oidSCEPTransactionID, Value: transactionID},
		{Type: oidSCEPSenderNonce, Value: nonce},
	}
	if err := sd.AddSigner(clientCert, clientKey, pkcs7.SignerInfoConfig{ExtraSignedAttributes: attrs}); err != nil {
		return nil, fmt.Errorf("scep: sign request: %w", err)
	}
	return sd.Finish()
}

// ParseSCEPResponse parses a SCEP CertRep, checks pkiStatus is success, decrypts the reply
// envelope with the requester's key, and returns the issued certificate DER. Used by SCEP
// clients and tests.
func ParseSCEPResponse(replyDER, recipientCertDER, recipientKeyPKCS8 []byte) ([]byte, error) {
	p7, err := pkcs7.Parse(replyDER)
	if err != nil {
		return nil, fmt.Errorf("scep: parse CertRep: %w", err)
	}
	if err := p7.Verify(); err != nil {
		return nil, fmt.Errorf("scep: verify CertRep signature: %w", err)
	}
	var status string
	if err := p7.UnmarshalSignedAttribute(oidSCEPPKIStatus, &status); err != nil {
		return nil, fmt.Errorf("scep: read pkiStatus: %w", err)
	}
	if status != scepStatusSuccess {
		return nil, fmt.Errorf("scep: CA returned pkiStatus %q (not success)", status)
	}
	recipientCert, err := x509.ParseCertificate(recipientCertDER)
	if err != nil {
		return nil, fmt.Errorf("scep: parse recipient cert: %w", err)
	}
	recipientKey, err := rsaKeyFromPKCS8(recipientKeyPKCS8)
	if err != nil {
		return nil, err
	}
	env, err := pkcs7.Parse(p7.Content)
	if err != nil {
		return nil, fmt.Errorf("scep: parse reply envelope: %w", err)
	}
	inner, err := env.Decrypt(recipientCert, recipientKey)
	if err != nil {
		return nil, fmt.Errorf("scep: decrypt reply: %w", err)
	}
	innerP7, err := pkcs7.Parse(inner)
	if err != nil || len(innerP7.Certificates) == 0 {
		return nil, fmt.Errorf("scep: reply carried no certificate: %w", err)
	}
	return innerP7.Certificates[0].Raw, nil
}

func rsaKeyFromPKCS8(pkcs8 []byte) (*rsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("scep: parse RSA key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("scep: key is not RSA (SCEP requires RSA key transport)")
	}
	return rk, nil
}

// scepReplyKey is referenced to keep the stdcrypto import meaningful even if the CMS
// library's signatures change; AddSigner accepts an stdcrypto.PrivateKey (*rsa.PrivateKey
// satisfies it).
var _ stdcrypto.PrivateKey = (*rsa.PrivateKey)(nil)
