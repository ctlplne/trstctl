// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package deviceattest_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// P12 on a software TPM: the factory station's delegated CA key and the
// device's own key both live in swtpm. The station certifies the device's
// TPM-made CSR as a client-only birth certificate through its key handle, and
// the certificate carries exactly the device's TPM key. Selected by
// TRSTCTL_SWTPM_PATH in the container harness.
func TestSwtpmFactoryStationCertifiesADeviceKeyP12(t *testing.T) {
	path := os.Getenv("TRSTCTL_SWTPM_PATH")
	if path == "" {
		t.Skip("TRSTCTL_SWTPM_PATH is required")
	}
	dev, err := tpm.OpenDevice(tpm.DeviceConfig{Path: path, PersistentHandleBase: 0x81019200})
	if err != nil {
		t.Fatal(err)
	}
	backend := tpm.New(dev)
	t.Cleanup(func() { _ = backend.Close() })
	ctx := context.Background()
	stationHandle, stationCSR, err := trstcrypto.GenerateEdgeCAKeyHandleAndCSR(ctx, "factory-station-p12", "line 1 station", trstcrypto.ECDSAP256, backend)
	if err != nil {
		t.Fatalf("station key in the TPM: %v", err)
	}
	const device = "sn-0001.devices.example.test"
	deviceHandle, deviceCSR, err := trstcrypto.GenerateEdgeCAKeyHandleAndCSR(ctx, "factory-device-p12", device, trstcrypto.ECDSAP256, backend)
	if err != nil {
		t.Fatalf("device key in the TPM: %v", err)
	}
	parentSigner, err := trstcrypto.GenerateLockedKey(trstcrypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parentSigner.Destroy)
	parent, err := trstcrypto.SelfSignedHierarchyCA(parentSigner, trstcrypto.HierarchyCAProfile{
		CommonName: "factory parent", MaxPathLen: 1, TTL: 24 * time.Hour, PermittedDNSDomains: []string{"devices.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trstcrypto.MintDelegatedEdgeCAFromCSR(parent.CertificateDER, parentSigner, stationCSR, trstcrypto.EdgeCARequest{
		CommonName: "line 1 station", PermittedDNSDomains: []string{"devices.example.test"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := trstcrypto.IssueEdgeLeafWithKeyHandle(ctx, delegation.CertificatePEM, stationHandle, backend, trstcrypto.EdgeLeafRequest{
		CommonName: device, TTL: 30 * time.Minute, CSRDER: deviceCSR, ClientAuthOnly: true,
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("birth certificate through the station's TPM key: %v", err)
	}
	cert, err := x509.ParseCertificate(leaf.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(delegation.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("birth certificate not signed by the station's TPM key: %v", err)
	}
	public, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(public, deviceHandle.PublicKeyDER) || len(leaf.LeafKeyPEM) != 0 {
		t.Fatal("the birth certificate does not certify the device's TPM key")
	}
	t.Logf("SWTPM_FACTORY_BIRTH_OK serial=%s", leaf.SerialHex)
}
