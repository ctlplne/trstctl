// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package deviceattest_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// TestSwtpmHostKeyIsCertifiedAndVerifiedTPMO1 (swtpm): a host endpoint key the
// TPM generates under the SRK signs its own CSR through the TPM; TPM2_Certify
// under a separately certified attestation key, wrapped over SHA-256 of the
// job's binding, verifies as device-bound custody of exactly the CSR's key;
// a binding for another job, or another CSR, is refused; the evidence
// re-verifies offline against a certificate for the key; and the key file is
// the TPM's wrapping, no software private key.
func TestSwtpmHostKeyIsCertifiedAndVerifiedTPMO1(t *testing.T) {
	path := os.Getenv("TRSTCTL_SWTPM_PATH")
	if path == "" {
		t.Skip("TRSTCTL_SWTPM_PATH is required")
	}
	dev, err := tpm.OpenDevice(tpm.DeviceConfig{Path: path, PersistentHandleBase: 0x8101a000})
	if err != nil {
		t.Fatal(err)
	}
	backend := tpm.New(dev)
	t.Cleanup(func() { _ = backend.Close() })
	host, ok := dev.(tpm.HostKeyDevice)
	if !ok {
		t.Fatal("the TPM device has no host key support")
	}
	file, publicDER, err := host.CreateHostKey()
	if err != nil {
		t.Fatalf("create host key: %v", err)
	}
	if !bytes.Contains(file, []byte("BEGIN TSS2 PRIVATE KEY")) || bytes.Contains(file, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(file, []byte("BEGIN EC PRIVATE KEY")) {
		t.Fatalf("the host key file is not the TPM's wrapping:\n%s", file)
	}
	csrDER, err := trstcrypto.CreateCertificateRequest(trstcrypto.CertificateRequestTemplate{CommonName: "web.lab.test", DNSNames: []string{"web.lab.test"}},
		tpm.HostKeySigner(host, file, publicDER))
	if err != nil {
		t.Fatalf("CSR signed by the TPM: %v", err)
	}
	aik, _, err := trstcrypto.GenerateEdgeCAKeyHandleAndCSR(context.Background(), "host-key-test-aik", "host key attestation key", trstcrypto.ECDSAP256, backend)
	if err != nil {
		t.Fatalf("generate the attestation key: %v", err)
	}
	rootPEM, aikChain := testTPMAIKCertificate(t, aik.PublicKeyDER)
	binding, err := deviceattest.HostKeyBinding(42, csrDER)
	if err != nil {
		t.Fatal(err)
	}
	certify := func(q []byte) (trstcrypto.EdgeTPMCertification, error) {
		return host.CertifyHostKey(file, aik.KeyID, q, nil)
	}
	credential, err := deviceattest.CreateHostKeyTPMCredential(binding, csrDER, publicDER, aik, aikChain, certify)
	if err != nil {
		t.Fatalf("attest the host key: %v", err)
	}
	now := time.Now().UTC()
	result, err := deviceattest.VerifyHostKeyAttestation(credential, binding, csrDER, [][]byte{rootPEM}, now)
	if err != nil || !result.DeviceBound {
		t.Fatalf("verify: %+v %v", result, err)
	}
	other, err := deviceattest.HostKeyBinding(43, csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deviceattest.VerifyHostKeyAttestation(credential, other, csrDER, [][]byte{rootPEM}, now); err == nil {
		t.Fatal("the attestation verified for another job's binding")
	}
	otherFile, otherDER, err := host.CreateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	otherCSR, err := trstcrypto.CreateCertificateRequest(trstcrypto.CertificateRequestTemplate{CommonName: "web.lab.test"}, tpm.HostKeySigner(host, otherFile, otherDER))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deviceattest.VerifyHostKeyAttestation(credential, binding, otherCSR, [][]byte{rootPEM}, now); err == nil {
		t.Fatal("the attestation verified for another CSR")
	}
	certificate := fixtureCertificateForCSR(t, csrDER, now)
	if _, err := deviceattest.VerifyTPMCustodyEvidence(deviceattest.TPMCustodyEvidence{Credential: credential, Binding: binding, VerifiedAt: now},
		certificate, [][]byte{rootPEM}); err != nil {
		t.Fatalf("the custody evidence does not re-verify offline: %v", err)
	}
	t.Log("SWTPM_HOST_KEY_OK")
}
