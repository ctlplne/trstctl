// SPDX-License-Identifier: MPL-2.0

package azurekv_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/azurekv"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func TestNativeKeysCAIssuesThroughDigestSigner(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caCert, err := crypto.SelfSignedHierarchyCA(caKey, crypto.HierarchyCAProfile{CommonName: "Azure Managed HSM CA", MaxPathLen: 0, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := azurekv.NewKeysCA(azurekv.KeysCAConfig{Name: "azure-native", CACertificatePEM: caCert.CertificatePEM}, caKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	csr := azurekvCSR(t, "native.azure.test")
	issued, err := plugin.Issue(context.Background(), ca.IssueRequest{CSR: csr, DNSNames: []string{"native.azure.test"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(issued.CertificatePEM)
	if err != nil || info.SerialNumber == "" {
		t.Fatalf("issued info = %+v, %v", info, err)
	}
	plugin.Destroy()
	if _, err := plugin.Issue(context.Background(), ca.IssueRequest{CSR: csr, DNSNames: []string{"native.azure.test"}}); err == nil {
		t.Fatal("destroyed native Azure CA still issued")
	}
}

func TestNativeKeysCARejectsCertificateKeyMismatch(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	otherKey, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherKey.Destroy)
	caCert, err := crypto.SelfSignedHierarchyCA(caKey, crypto.HierarchyCAProfile{CommonName: "Azure Managed HSM CA", MaxPathLen: 0, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := azurekv.NewKeysCA(azurekv.KeysCAConfig{CACertificatePEM: caCert.CertificatePEM}, otherKey, nil); err == nil {
		t.Fatal("accepted a CA certificate that does not match the Azure key")
	}
}
