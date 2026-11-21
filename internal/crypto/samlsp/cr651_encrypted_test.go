// SPDX-License-Identifier: BUSL-1.1

package samlsp

import (
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/xmlenc"
	"trstctl.com/trstctl/internal/crypto"
)

func cr651EncryptedSP(t *testing.T) (*ServiceProvider, sloIdP, *x509.Certificate) {
	t.Helper()
	idp := newSLOIdP(t, false)
	cfg := artifactConfig(idp.metadata)
	cfg.ResponseBinding = ""
	certDER, keyPKCS8 := encryptionIdentity(t, crypto.RSA2048)
	cfg.EncryptionCertDER, cfg.EncryptionKeyPKCS8 = certDER, keyPKCS8
	sp, err := NewServiceProvider(cfg)
	if err != nil || !sp.DecryptsAssertions() {
		t.Fatalf("encrypted service provider = %v %v", sp, err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return sp, idp, cert
}

func cr651EncryptedRequest(t *testing.T, idp sloIdP, cert *x509.Certificate, cipher xmlenc.BlockCipher, plaintext []byte, mutate func(*etree.Element)) *http.Request {
	t.Helper()
	transport := xmlenc.OAEP()
	transport.BlockCipher = cipher
	encrypted, err := transport.Encrypt(cert, plaintext, make([]byte, 12))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(encrypted)
	}
	doc := etree.NewDocument()
	response := doc.CreateElement("samlp:Response")
	response.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	response.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	response.CreateAttr("ID", "id-cr651-encrypted")
	response.CreateAttr("Version", "2.0")
	response.CreateAttr("IssueInstant", cr651Time(time.Now()))
	response.CreateElement("saml:Issuer").SetText(idp.entityID)
	response.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	response.CreateElement("saml:EncryptedAssertion").AddChild(encrypted)
	encoded, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(encoded)}}
	r, err := http.NewRequest(http.MethodPost, cr651ACS, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func cr651ReplaceCiphertext(raw []byte) func(*etree.Element) {
	return func(encrypted *etree.Element) {
		value := encrypted.FindElement("./CipherData/CipherValue")
		value.SetText(base64.StdEncoding.EncodeToString(raw))
	}
}

func TestCR651MalformedEncryptedAssertionsAreRejectedWithoutPanic(t *testing.T) {
	sp, idp, cert := cr651EncryptedSP(t)
	assertion := []byte(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a" Version="2.0" IssueInstant="` + cr651Time(time.Now()) + `"/>`)
	cases := map[string]*http.Request{
		"short GCM nonce":   cr651EncryptedRequest(t, idp, cert, xmlenc.AES128GCM, assertion, cr651ReplaceCiphertext([]byte{1, 2, 3, 4, 5})),
		"partial CBC block": cr651EncryptedRequest(t, idp, cert, xmlenc.AES256CBC, assertion, cr651ReplaceCiphertext(make([]byte, 16+17))),
		"no decrypted root": cr651EncryptedRequest(t, idp, cert, xmlenc.AES256CBC, []byte(`<!-- no assertion here -->`), nil),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			_, panicValue, err := cr651Verify(sp, r)
			if panicValue != nil || err == nil {
				t.Fatalf("malformed encrypted assertion = err %v, panic %v; want a refusal without panic", err, panicValue)
			}
		})
	}
}
