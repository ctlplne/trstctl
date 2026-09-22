// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Ed25519 gives the opaque encoder an independent verifier in crypto/x509.
// Production ML-DSA additionally runs against stock OpenSSL in internal/pqc.
func TestOpaqueCSRConstructorSignsFinalSubjectAndPreservesMetadata(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(private)
	signer := &opaqueCSRTestSigner{public: pub, sign: func(message []byte) ([]byte, error) {
		return ed25519.Sign(private, message), nil
	}}
	template := CertificateRequestTemplate{
		CommonName: "api.example.test", DNSNames: []string{"api.example.test", "alt.example.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, EmailAddresses: []string{"owner@example.test"},
		URIs: []string{"spiffe://example.test/api"}, RequestedEKUs: []string{"serverAuth"},
		ExtraExtensions: []CertificateExtension{{OID: "1.2.3.4.5", Critical: true, Value: []byte{5, 0}}},
	}
	der, err := CreateOpaqueCertificateRequest(template, "1.3.101.112", signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckSignature(); err != nil {
		t.Fatalf("final CSR signature failed independent verification: %v", err)
	}
	actual, ok := parsed.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(actual, pub) {
		t.Fatal("metadata key replaced the actual subject key")
	}
	info, err := InspectCSR(der)
	if err != nil {
		t.Fatal(err)
	}
	if info.CommonName != template.CommonName || !reflect.DeepEqual(info.DNSNames, template.DNSNames) || !reflect.DeepEqual(info.IPAddresses, []string{"127.0.0.1"}) || !reflect.DeepEqual(info.EmailAddresses, template.EmailAddresses) || !reflect.DeepEqual(info.URIs, template.URIs) || !reflect.DeepEqual(info.RequestedEKUs, template.RequestedEKUs) {
		t.Fatalf("CSR lost requested metadata: %+v", info)
	}
	found := false
	for _, extension := range parsed.Extensions {
		if extension.Id.String() == "1.2.3.4.5" {
			found = extension.Critical && bytes.Equal(extension.Value, []byte{5, 0})
		}
	}
	if !found {
		t.Fatal("custom critical extension was changed or dropped")
	}
	tampered := append([]byte(nil), der...)
	tampered[len(tampered)-1] ^= 1
	if err := VerifyCertificateRequest(tampered); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestOpaqueCSRConstructorRejectsUnusableInputsAndSignerFailures(t *testing.T) {
	failure := errors.New("subject signer unavailable")
	for _, tc := range []struct {
		name, oid string
		signer    Signer
		want      error
	}{
		{name: "nil signer", oid: "1.3.101.112"},
		{name: "invalid oid", oid: "bad", signer: &opaqueCSRTestSigner{public: []byte{1}}},
		{name: "invalid oid arcs", oid: "3.4", signer: &opaqueCSRTestSigner{public: []byte{1}}},
		{name: "empty public key", oid: "1.3.101.112", signer: &opaqueCSRTestSigner{}},
		{name: "empty signature", oid: "1.3.101.112", signer: &opaqueCSRTestSigner{public: []byte{1}}},
		{name: "signer failure", oid: "1.3.101.112", signer: &opaqueCSRTestSigner{public: []byte{1}, sign: func([]byte) ([]byte, error) { return nil, failure }}, want: failure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := CreateOpaqueCertificateRequest(CertificateRequestTemplate{CommonName: "api.example.test"}, tc.oid, tc.signer)
			if err == nil || len(der) != 0 {
				t.Fatal("invalid construction returned a request")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("signer error lost: %v", err)
			}
		})
	}
}

type opaqueCSRTestSigner struct {
	public []byte
	sign   func([]byte) ([]byte, error)
}

func (s *opaqueCSRTestSigner) Public() PublicKey    { return PublicKey{DER: s.public} }
func (s *opaqueCSRTestSigner) Algorithm() Algorithm { return Ed25519 }
func (s *opaqueCSRTestSigner) Sign(message []byte, _ SignOptions) ([]byte, error) {
	if s.sign != nil {
		return s.sign(message)
	}
	return nil, nil
}
