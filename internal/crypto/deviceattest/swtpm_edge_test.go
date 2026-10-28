// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package deviceattest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// TestSwtpmEdgeTPMCertifiesTheActualCSRKey runs TPM2_Certify through swtpm,
// then passes the resulting WebAuthn envelope through the same parser as the
// served mint route. It is selected by TRSTCTL_SWTPM_PATH in the local lab.
func TestSwtpmEdgeTPMCertifiesTheActualCSRKey(t *testing.T) {
	path := os.Getenv("TRSTCTL_SWTPM_PATH")
	if path == "" {
		t.Skip("TRSTCTL_SWTPM_PATH is required")
	}
	dev, err := tpm.OpenDevice(tpm.DeviceConfig{Path: path, PersistentHandleBase: 0x81019000})
	if err != nil {
		t.Fatal(err)
	}
	backend := tpm.New(dev)
	t.Cleanup(func() { _ = backend.Close() })
	ctx := context.Background()
	edge, csrDER, err := trstcrypto.GenerateEdgeCAKeyHandleAndCSR(ctx, "edge-attest-test-ca", "edge attested CA", trstcrypto.ECDSAP256, backend)
	if err != nil {
		t.Fatalf("generate TPM edge key and CSR: %v", err)
	}
	aik, _, err := trstcrypto.GenerateEdgeCAKeyHandleAndCSR(ctx, "edge-attest-test-aik", "edge attestation key", trstcrypto.ECDSAP256, backend)
	if err != nil {
		t.Fatalf("generate separate TPM attestation key: %v", err)
	}
	rootPEM, aikChain := testTPMAIKCertificate(t, aik.PublicKeyDER)
	wrongHandle := edge
	wrongHandle.PublicKeyDER = aik.PublicKeyDER
	if _, err := deviceattest.CreateEdgeTPMCredential("tenant-a", "segment-a", csrDER, wrongHandle, aik, aikChain, nil, backend); err == nil {
		t.Fatal("edge CSR was accepted with another TPM key's public handle")
	}
	wrongAIK := aik
	wrongAIK.PublicKeyDER = edge.PublicKeyDER
	if _, err := deviceattest.CreateEdgeTPMCredential("tenant-a", "segment-a", csrDER, edge, wrongAIK, aikChain, nil, backend); err == nil {
		t.Fatal("AIK certificate was accepted with a different TPM handle")
	}
	credential, err := deviceattest.CreateEdgeTPMCredential("tenant-a", "segment-a", csrDER, edge, aik, aikChain, nil, backend)
	if err != nil {
		t.Fatalf("certify real TPM edge key: %v", err)
	}
	challenge := trstcrypto.EdgeAttestationChallenge("tenant-a", "segment-a", csrDER)
	verified, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(credential, challenge, [][]byte{rootPEM}, []int64{-7}, time.Now().UTC())
	if err != nil {
		t.Fatalf("server parser refused real TPM certification: %v", err)
	}
	csrDigest, err := deviceattest.CSRPublicKeySHA256(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if string(verified.PublicKeySHA256) != string(csrDigest) {
		t.Fatal("TPM certified a different key from the edge CSR")
	}
	// A131: a key the TPM generated as a fixedTPM/fixedParent object is
	// reported device-bound from the attributes the TPM itself certified.
	if !verified.DeviceBound {
		t.Fatal("the real TPM certification did not report a device-bound key")
	}
	otherChallenge := trstcrypto.EdgeAttestationChallenge("tenant-a", "segment-b", csrDER)
	if _, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(credential, otherChallenge, [][]byte{rootPEM}, []int64{-7}, time.Now().UTC()); err == nil {
		t.Fatal("attestation replayed into another segment")
	}
	otherRoot, _ := testTPMAIKCertificate(t, aik.PublicKeyDER)
	if _, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(credential, challenge, [][]byte{otherRoot}, []int64{-7}, time.Now().UTC()); err == nil {
		t.Fatal("untrusted attestation root was accepted")
	}
	t.Logf("SWTPM_EDGE_CERTIFY_OK edge_handle=%s aik_handle=%s", edge.KeyID, aik.KeyID)
}

// A220: a renewal has the SAME swtpm key sign a fresh CSR and certifies it
// again with TPM2_Certify. The shared verifier the control plane runs for a
// mint and a renewal accepts it with the same CSR key as the mint, and refuses
// a credential whose AIK does not chain to the pinned root, which is the
// failed attestation that leaves a delegation to expire.
func TestSwtpmEdgeRenewalCertifiesTheSameKeyAgain(t *testing.T) {
	path := os.Getenv("TRSTCTL_SWTPM_PATH")
	if path == "" {
		t.Skip("TRSTCTL_SWTPM_PATH is required")
	}
	dev, err := tpm.OpenDevice(tpm.DeviceConfig{Path: path, PersistentHandleBase: 0x81019100})
	if err != nil {
		t.Fatal(err)
	}
	backend := tpm.New(dev)
	t.Cleanup(func() { _ = backend.Close() })
	ctx := context.Background()
	edge, mintCSR, err := trstcrypto.GenerateEdgeCAKeyHandleAndCSR(ctx, "edge-renewal-test-ca", "edge renewal CA", trstcrypto.ECDSAP256, backend)
	if err != nil {
		t.Fatalf("generate TPM edge key and CSR: %v", err)
	}
	aik, _, err := trstcrypto.GenerateEdgeCAKeyHandleAndCSR(ctx, "edge-renewal-test-aik", "edge renewal attestation key", trstcrypto.ECDSAP256, backend)
	if err != nil {
		t.Fatalf("generate TPM attestation key: %v", err)
	}
	rootPEM, aikChain := testTPMAIKCertificate(t, aik.PublicKeyDER)
	now := time.Now().UTC()
	mintCredential, err := deviceattest.CreateEdgeTPMCredential("tenant-a", "segment-a", mintCSR, edge, aik, aikChain, nil, backend)
	if err != nil {
		t.Fatalf("certify the mint CSR: %v", err)
	}
	minted, err := deviceattest.VerifyEdgeCAAttestation(mintCredential, "tenant-a", "segment-a", mintCSR, [][]byte{rootPEM}, "tpm2", now)
	if err != nil {
		t.Fatalf("the mint attestation was refused: %v", err)
	}
	renewalCSR, err := trstcrypto.EdgeCSRForKeyHandle(ctx, edge, backend, "edge renewal CA")
	if err != nil {
		t.Fatalf("the TPM key did not sign a renewal CSR: %v", err)
	}
	if string(renewalCSR) == string(mintCSR) {
		t.Fatal("the renewal CSR is the mint CSR; a renewal needs a fresh request")
	}
	renewalCredential, err := deviceattest.CreateEdgeTPMCredential("tenant-a", "segment-a", renewalCSR, edge, aik, aikChain, nil, backend)
	if err != nil {
		t.Fatalf("certify the renewal CSR: %v", err)
	}
	renewed, err := deviceattest.VerifyEdgeCAAttestation(renewalCredential, "tenant-a", "segment-a", renewalCSR, [][]byte{rootPEM}, "tpm2", now)
	if err != nil {
		t.Fatalf("the fresh renewal attestation was refused: %v", err)
	}
	if string(renewed.CSRKeySHA256) != string(minted.CSRKeySHA256) || !renewed.Attested.DeviceBound {
		t.Fatal("the renewal attested a different or exportable key")
	}
	if _, err := deviceattest.VerifyEdgeCAAttestation(mintCredential, "tenant-a", "segment-a", renewalCSR, [][]byte{rootPEM}, "tpm2", now); err == nil {
		t.Fatal("the mint's credential vouched for the renewal CSR")
	}
	otherRoot, _ := testTPMAIKCertificate(t, aik.PublicKeyDER)
	if _, err := deviceattest.VerifyEdgeCAAttestation(renewalCredential, "tenant-a", "segment-a", renewalCSR, [][]byte{otherRoot}, "tpm2", now); err == nil {
		t.Fatal("a renewal attestation through an unpinned root was accepted")
	}
	t.Logf("SWTPM_EDGE_RENEWAL_OK edge_handle=%s", edge.KeyID)
}

func testTPMAIKCertificate(t *testing.T, aikPublicDER []byte) ([]byte, []byte) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "QA swtpm attestation root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(aikPublicDER)
	if err != nil {
		t.Fatal(err)
	}
	nameDER, err := asn1.Marshal(pkix.RDNSequence{{
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 1}, Value: "id:4D534654"},
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 2}, Value: "trstctl-swtpm"},
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 3}, Value: "id:00010000"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sanDER, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: nameDER}})
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 3}},
		ExtraExtensions:    []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: sanDER}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, publicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), rootPEM...)
	return rootPEM, chain
}
