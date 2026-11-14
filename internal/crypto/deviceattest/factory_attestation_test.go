// SPDX-License-Identifier: BUSL-1.1

package deviceattest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
)

// P12-L1: a device's TPM attestation of its own key verifies for its batch,
// its name and its CSR against the batch's roots, and for a birth
// certificate of that key; it vouches for no other device, batch, root or
// key, and a key the TPM could release is refused.
func TestFactoryDeviceAttestationBindsBatchDeviceAndKeyP12L1(t *testing.T) {
	now := time.Now().UTC()
	device, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	const tenant, batch, name = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "sn-0001.devices.example.test"
	challenge := trstcrypto.EdgeAttestationChallenge(tenant, deviceattest.FactoryAttestationSegment(batch, name), device.CSRDER())
	credential, err := device.CredentialJSON(challenge)
	if err != nil {
		t.Fatal(err)
	}
	roots := [][]byte{device.RootPEM()}
	if err := deviceattest.VerifyFactoryDeviceAttestation(credential, tenant, batch, name, device.CSRDER(), nil, roots, now); err != nil {
		t.Fatalf("the device's own attestation: %v", err)
	}
	refused := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, deviceattest.ErrEdgeAttestationRefused) {
			t.Fatalf("%s: %v; want refused", what, err)
		}
	}
	refused("another device", deviceattest.VerifyFactoryDeviceAttestation(credential, tenant, batch, "sn-0002.devices.example.test", device.CSRDER(), nil, roots, now))
	refused("another batch", deviceattest.VerifyFactoryDeviceAttestation(credential, tenant, "33333333-3333-4333-8333-333333333333", name, device.CSRDER(), nil, roots, now))
	refused("another root", deviceattest.VerifyFactoryDeviceAttestation(credential, tenant, batch, name, device.CSRDER(), nil, [][]byte{other.RootPEM()}, now))
	refused("another CSR", deviceattest.VerifyFactoryDeviceAttestation(credential, tenant, batch, name, other.CSRDER(), nil, roots, now))
	refused("no attestation", deviceattest.VerifyFactoryDeviceAttestation(nil, tenant, batch, name, device.CSRDER(), nil, roots, now))
	releasable, err := device.DuplicableCredentialJSON(challenge)
	if err != nil {
		t.Fatal(err)
	}
	refused("a key the TPM could release", deviceattest.VerifyFactoryDeviceAttestation(releasable, tenant, batch, name, device.CSRDER(), nil, roots, now))
	// An edge host's attestation for a segment is not a device's.
	edge, err := device.CredentialJSON(trstcrypto.EdgeAttestationChallenge(tenant, batch, device.CSRDER()))
	if err != nil {
		t.Fatal(err)
	}
	refused("an edge segment's attestation", deviceattest.VerifyFactoryDeviceAttestation(edge, tenant, batch, name, device.CSRDER(), nil, roots, now))

	// With the birth certificate: it must certify the attested key.
	stationKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	station := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "station"}, NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	birth := func(csrDER []byte) []byte {
		t.Helper()
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
			station, csr.PublicKey, stationKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	if err := deviceattest.VerifyFactoryDeviceAttestation(credential, tenant, batch, name, device.CSRDER(), birth(device.CSRDER()), roots, now); err != nil {
		t.Fatalf("the birth certificate of the attested key: %v", err)
	}
	refused("a birth certificate of another key", deviceattest.VerifyFactoryDeviceAttestation(credential, tenant, batch, name, device.CSRDER(), birth(other.CSRDER()), roots, now))
}
