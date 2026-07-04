// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"encoding/asn1"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

type cmpStrictMessage struct {
	Header     asn1.RawValue
	Body       asn1.RawValue
	Protection asn1.BitString  `asn1:"optional,explicit,tag:0"`
	ExtraCerts []asn1.RawValue `asn1:"optional,explicit,tag:1"`
}

func TestCMPRequestRejectsTrailingBytes(t *testing.T) {
	reqDER, _ := buildCMPStrictFixtures(t)

	if _, err := crypto.ParseCMPRequest(append(append([]byte(nil), reqDER...), 0)); err == nil {
		t.Fatal("ParseCMPRequest accepted a valid PKIMessage with trailing bytes")
	}
}

func TestCMPResponseRejectsTrailingBytes(t *testing.T) {
	_, respDER := buildCMPStrictFixtures(t)

	if _, err := crypto.ParseCMPResponse(append(append([]byte(nil), respDER...), 0)); err == nil {
		t.Fatal("ParseCMPResponse accepted a valid PKIMessage with trailing bytes")
	}
}

func TestCMPResponseRejectsNestedTrailingBytes(t *testing.T) {
	_, respDER := buildCMPStrictFixtures(t)
	var msg cmpStrictMessage
	if rest, err := asn1.Unmarshal(respDER, &msg); err != nil {
		t.Fatalf("parse valid CMP response: %v", err)
	} else if len(rest) != 0 {
		t.Fatalf("test fixture has %d trailing response bytes", len(rest))
	}

	msg.Body.Bytes = append(append([]byte(nil), msg.Body.Bytes...), 0)
	msg.Body.FullBytes = nil
	withNestedTrailing, err := asn1.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal CMP response with nested trailing bytes: %v", err)
	}

	if _, err := crypto.ParseCMPResponse(withNestedTrailing); err == nil {
		t.Fatal("ParseCMPResponse accepted a CertRepMessage with trailing bytes")
	}
}

func buildCMPStrictFixtures(t *testing.T) (reqDER, respDER []byte) {
	t.Helper()

	clientSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	t.Cleanup(clientSigner.Destroy)
	clientCertDER, err := crypto.SelfSignedCACert(clientSigner, "cmp-client", time.Hour)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	clientKeyPKCS8, err := clientSigner.PKCS8()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "cmp-client"}, clientSigner)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	reqDER, err = crypto.BuildCMPRequest(csrDER, clientCertDER, clientKeyPKCS8, []byte("strict-txid"), []byte("strict-nonce"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req, err := crypto.ParseCMPRequest(reqDER)
	if err != nil {
		t.Fatalf("parse valid request: %v", err)
	}

	caSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	t.Cleanup(caSigner.Destroy)
	caCertDER, err := crypto.SelfSignedCACert(caSigner, "cmp-ca", time.Hour)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caKeyPKCS8, err := caSigner.PKCS8()
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	leafDER, err := crypto.SignLeafFromCSR(caCertDER, caSigner, csrDER, time.Hour)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	respDER, err = crypto.BuildCMPResponse(leafDER, caCertDER, caKeyPKCS8, req)
	if err != nil {
		t.Fatalf("build response: %v", err)
	}
	if _, err := crypto.ParseCMPResponse(respDER); err != nil {
		t.Fatalf("parse valid response: %v", err)
	}
	return reqDER, respDER
}
