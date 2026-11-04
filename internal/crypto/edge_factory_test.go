// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

// P12: a factory station certifies a device's own key. The device makes its
// key and request (in its TPM or secure element); the station signs only what
// the request proves, under the delegation's constraints, as a client-only
// birth certificate, and never holds or writes a device key.
func TestEdgeStationCertifiesTheDeviceCSRP12(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	station := newEdgeHandleTestBackend("tpm2")
	t.Cleanup(station.destroy)
	handle, stationCSR, err := GenerateEdgeCAKeyHandleAndCSR(ctx, "tenant-a/line-1/generation-1", "line 1 station", ECDSAP256, station)
	if err != nil {
		t.Fatal(err)
	}
	parentSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parentSigner.Destroy)
	parent, err := SelfSignedHierarchyCA(parentSigner, HierarchyCAProfile{
		CommonName: "factory parent", MaxPathLen: 1, TTL: 24 * time.Hour, PermittedDNSDomains: []string{"devices.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := MintDelegatedEdgeCAFromCSR(parent.CertificateDER, parentSigner, stationCSR, EdgeCARequest{
		CommonName: "line 1 station", PermittedDNSDomains: []string{"devices.example.test"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(deviceKey.Destroy)
	const device = "sn-0001.devices.example.test"
	deviceCSR, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: device}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := IssueEdgeLeafWithKeyHandle(ctx, delegation.CertificatePEM, handle, station, EdgeLeafRequest{
		CommonName: device, TTL: 30 * time.Minute, CSRDER: deviceCSR, ClientAuthOnly: true,
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("birth certificate: %v", err)
	}
	if len(leaf.LeafKeyPEM) != 0 {
		t.Fatal("the station produced a key for a device that made its own")
	}
	cert, err := x509.ParseCertificate(leaf.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(mustParseCertificate(t, delegation.CertificateDER)); err != nil {
		t.Fatalf("birth certificate not signed by the station key: %v", err)
	}
	certPublic, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(certPublic) != string(deviceKey.Public().DER) {
		t.Fatal("the birth certificate does not certify the device's key")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || cert.Subject.CommonName != device {
		t.Fatalf("birth certificate subject %q usage %v", cert.Subject.CommonName, cert.ExtKeyUsage)
	}

	for name, req := range map[string]EdgeLeafRequest{
		"another device's request":      {CommonName: "sn-0002.devices.example.test", CSRDER: deviceCSR},
		"a request that is not a CSR":   {CommonName: device, CSRDER: []byte("not a request")},
		"a name outside the delegation": {CommonName: "sn-0001.other.example.test", CSRDER: deviceCSR},
	} {
		if _, err := IssueEdgeLeafWithKeyHandle(ctx, delegation.CertificatePEM, handle, station, req, time.Now().UTC()); err == nil {
			t.Fatalf("%s was certified", name)
		}
	}
	tampered := append([]byte(nil), deviceCSR...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := IssueEdgeLeafWithKeyHandle(ctx, delegation.CertificatePEM, handle, station, EdgeLeafRequest{
		CommonName: device, CSRDER: tampered}, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "CSR") {
		t.Fatalf("a tampered request = %v", err)
	}
}
