// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"encoding/pem"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func hostTestCredential(t *testing.T) (certPEM, keyPEM []byte, fingerprint string) {
	t.Helper()
	keyPEM, certPEM, err := crypto.GenerateUploadableRSAKeypair(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secret.Wipe(keyPEM) })
	info, err := certinfo.Inspect(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM, info.SHA256Fingerprint
}

func hostServerCredential(t *testing.T, name string) (certPEM, keyPEM []byte, fingerprint string) {
	certPEM, keyPEM, _, fingerprint = hostServerCredentialWithChain(t, name)
	return certPEM, keyPEM, fingerprint
}

func hostServerCredentialWithChain(t *testing.T, name string) (certPEM, keyPEM, chainPEM []byte, fingerprint string) {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "host test CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issuedPEM, err := crypto.SignServerCertFromCSR(caDER, ca, csr, []string{name}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	der, err := certinfo.LeafDER(issuedPEM)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err = key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secret.Wipe(keyPEM) })
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chainPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	info, err := certinfo.Inspect(der)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM, chainPEM, info.SHA256Fingerprint
}

func signHostCSRForTest(csrDER []byte) (certPEM, chainPEM []byte, fingerprint string, err error) {
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, nil, "", err
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "host renewal test CA", 24*time.Hour)
	if err != nil {
		return nil, nil, "", err
	}
	leafDER, err := crypto.SignLeafFromCSR(caDER, ca, csrDER, time.Hour)
	if err != nil {
		return nil, nil, "", err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	chainPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		return nil, nil, "", err
	}
	return certPEM, chainPEM, info.SHA256Fingerprint, nil
}
