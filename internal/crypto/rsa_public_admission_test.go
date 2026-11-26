// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

type rsaAdmissionCSR struct {
	Info      asn1.RawValue
	Algorithm asn1.RawValue
	Signature asn1.BitString
}

type rsaAdmissionCSRInfo struct {
	Version    int
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Attributes asn1.RawValue `asn1:"optional,tag:0"`
}

func TestUntrustedCSRRejectsOversizedRSABeforeSignatureWork(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "large.example"}}, private)
	if err != nil {
		t.Fatal(err)
	}
	var outer rsaAdmissionCSR
	if _, err := asn1.Unmarshal(csr, &outer); err != nil {
		t.Fatal(err)
	}
	var info rsaAdmissionCSRInfo
	if _, err := asn1.Unmarshal(outer.Info.FullBytes, &info); err != nil {
		t.Fatal(err)
	}
	huge := &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 9000), big.NewInt(1)), E: 65537}
	spki, err := x509.MarshalPKIXPublicKey(huge)
	if err != nil {
		t.Fatal(err)
	}
	info.PublicKey = asn1.RawValue{FullBytes: spki}
	infoDER, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	outer.Info = asn1.RawValue{FullBytes: infoDER}
	csr, err = asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]func([]byte) error{
		"verify":  VerifyCertificateRequest,
		"inspect": func(raw []byte) error { _, err := InspectCSR(raw); return err },
	} {
		if err := check(csr); err == nil || !strings.Contains(err.Error(), "8192") {
			t.Errorf("%s did not reject the RSA size before signature verification: %v", name, err)
		}
	}
}

func TestUntrustedRSAPublicKeyBounds(t *testing.T) {
	withinLimit := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 8191), E: 65537}
	if err := ValidateUntrustedPublicKey(withinLimit); err != nil {
		t.Fatalf("8192-bit key rejected: %v", err)
	}
	for _, exponent := range []int{1, 2, 65539} {
		if err := ValidateUntrustedPublicKey(&rsa.PublicKey{N: big.NewInt(17), E: exponent}); err == nil {
			t.Errorf("exponent %d admitted", exponent)
		}
	}
}

func TestSCEPRejectsOversizedCMSSignerBeforeVerification(t *testing.T) {
	client, err := GenerateLockedKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Destroy)
	clientKey, err := client.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secret.Wipe(clientKey) })
	private, err := rsaKeyFromPKCS8(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	huge := &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 9000), big.NewInt(1)), E: 65537}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "large-cms"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	clientCert, err := x509.CreateCertificate(rand.Reader, template, template, huge, private)
	if err != nil {
		t.Fatal(err)
	}
	ra, err := GenerateLockedKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ra.Destroy)
	raCert, err := SelfSignedCACert(ra, "scep-ra", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raKey, err := ra.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secret.Wipe(raKey) })
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "large-cms"}, client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := BuildSCEPRequest(csr, clientCert, clientKey, raCert, "rsa-admission")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSCEPRequest(request, raCert, raKey); err == nil || !strings.Contains(err.Error(), "8192") {
		t.Fatalf("oversized CMS signer reached signature verification: %v", err)
	}
}
