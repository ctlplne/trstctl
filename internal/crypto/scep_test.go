package crypto

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

func TestSCEPEnvelopesUseAES256CBC(t *testing.T) {
	caSigner, err := GenerateLockedKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caSigner.Destroy)
	caCertDER, err := SelfSignedCACert(caSigner, "SCEP AES CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caKeyPKCS8, err := caSigner.PKCS8()
	if err != nil {
		t.Fatal(err)
	}

	clientSigner, err := GenerateLockedKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clientSigner.Destroy)
	clientCertDER, err := SelfSignedCACert(clientSigner, "SCEP AES client", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyPKCS8, err := clientSigner.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "device-aes"}, clientSigner)
	if err != nil {
		t.Fatal(err)
	}

	requestDER, err := BuildSCEPRequest(csrDER, clientCertDER, clientKeyPKCS8, caCertDER, "txn-aes")
	if err != nil {
		t.Fatalf("BuildSCEPRequest: %v", err)
	}
	requestP7, err := safeParsePKCS7(requestDER)
	if err != nil {
		t.Fatalf("parse request SignedData: %v", err)
	}
	assertSCEPEnvelopeAlgorithm(t, "request", requestP7.Content, pkcs7.OIDEncryptionAlgorithmAES256CBC)

	req, err := ParseSCEPRequest(requestDER, caCertDER, caKeyPKCS8)
	if err != nil {
		t.Fatalf("ParseSCEPRequest: %v", err)
	}
	issuedCertDER, err := SignLeafFromCSR(caCertDER, caSigner, csrDER, time.Hour)
	if err != nil {
		t.Fatalf("SignLeafFromCSR: %v", err)
	}
	replyDER, err := BuildSCEPSuccess(issuedCertDER, caCertDER, caKeyPKCS8, req)
	if err != nil {
		t.Fatalf("BuildSCEPSuccess: %v", err)
	}
	replyP7, err := safeParsePKCS7(replyDER)
	if err != nil {
		t.Fatalf("parse reply SignedData: %v", err)
	}
	assertSCEPEnvelopeAlgorithm(t, "reply", replyP7.Content, pkcs7.OIDEncryptionAlgorithmAES256CBC)

	if _, err := ParseSCEPResponse(replyDER, clientCertDER, clientKeyPKCS8); err != nil {
		t.Fatalf("ParseSCEPResponse: %v", err)
	}
}

func assertSCEPEnvelopeAlgorithm(t *testing.T, name string, envelopeDER []byte, want asn1.ObjectIdentifier) {
	t.Helper()
	got := scepEnvelopeAlgorithmOID(t, envelopeDER)
	if !got.Equal(want) {
		t.Fatalf("%s envelope algorithm = %s, want %s", name, got.String(), want.String())
	}
}

func scepEnvelopeAlgorithmOID(t *testing.T, envelopeDER []byte) asn1.ObjectIdentifier {
	t.Helper()
	var content scepTestContentInfo
	rest, err := asn1.Unmarshal(envelopeDER, &content)
	if err != nil {
		t.Fatalf("parse envelope ContentInfo: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("parse envelope ContentInfo: %d trailing bytes", len(rest))
	}
	if !content.ContentType.Equal(pkcs7.OIDEnvelopedData) {
		t.Fatalf("envelope content type = %s, want %s", content.ContentType.String(), pkcs7.OIDEnvelopedData.String())
	}

	var envelope scepTestEnvelopedData
	rest, err = asn1.Unmarshal(content.Content.Bytes, &envelope)
	if err != nil {
		t.Fatalf("parse EnvelopedData: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("parse EnvelopedData: %d trailing bytes", len(rest))
	}
	return envelope.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm
}

type scepTestContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type scepTestEnvelopedData struct {
	Version              int
	RecipientInfos       asn1.RawValue
	EncryptedContentInfo scepTestEncryptedContentInfo
}

type scepTestEncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}
