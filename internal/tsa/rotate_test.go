// SPDX-License-Identifier: BUSL-1.1

package tsa_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/tsa"
)

// A145: rotating the authority moves later tokens onto the new certificate and
// key under the same root, keeps the serial sequence, and refuses a certificate
// that does not certify the new key or is not a timestamping end entity.
func TestRotateMovesLaterTokensOntoTheNewCertificate(t *testing.T) {
	root, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Destroy)
	rootDER, err := crypto.SelfSignedCACert(root, "rotation root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(name string) (*crypto.LockedSigner, []byte) {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name}, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := crypto.SignTimestampingCertFromCSR(rootDER, root, csr, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return key, cert
	}
	firstKey, firstCert := mint("first TSA")
	a, err := tsa.New(tsa.Config{TenantID: "t1", TSACertDER: firstCert, TSASigner: firstKey})
	if err != nil {
		t.Fatal(err)
	}
	imprint := crypto.SHA256Sum([]byte("before"))
	before, err := a.Timestamp(context.Background(), imprint)
	if err != nil || !bytes.Equal(before.TSACertDER, firstCert) {
		t.Fatalf("first token = %v", err)
	}
	secondKey, secondCert := mint("second TSA")
	if err := a.Rotate(secondCert, firstKey); err == nil {
		t.Fatal("a certificate for another key was accepted")
	}
	caCert, err := crypto.SelfSignedCACert(secondKey, "not a TSA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Rotate(caCert, secondKey); err == nil {
		t.Fatal("a CA certificate was accepted as a TSA certificate")
	}
	if err := a.Rotate(secondCert, secondKey); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Certificate(), secondCert) {
		t.Fatal("the authority reports the old certificate after rotating")
	}
	after, err := a.Timestamp(context.Background(), crypto.SHA256Sum([]byte("after")))
	if err != nil || !bytes.Equal(after.TSACertDER, secondCert) || after.Info.SerialNumber != before.Info.SerialNumber+1 {
		t.Fatalf("token after rotation = %+v, %v", after.Info, err)
	}
	if err := tsa.Verify(after, crypto.SHA256Sum([]byte("after")), rootDER); err != nil {
		t.Fatalf("a token from the rotated certificate does not verify: %v", err)
	}
	if err := tsa.Verify(before, imprint, rootDER); err != nil {
		t.Fatalf("a token from before the rotation stopped verifying: %v", err)
	}
}
