// SPDX-License-Identifier: BUSL-1.1

package ca

import (
	"crypto/x509"
	"slices"
	"testing"
	"time"
)

// CR-052: a CA whose extended key usage constraint includes
// anyExtendedKeyUsage is unrestricted; that usage is never copied onto a leaf
// it issues, so the leaf keeps the CA's other usages and no more.
func TestHierarchyLeafNeverInheritsAnyEKU(t *testing.T) {
	root, err := NewRoot(CASpec{CommonName: "CR-052 root", EKUs: []string{"serverAuth", "any"}, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Destroy)
	issued, err := root.IssueLeaf(leafCSR(t, "svc.cr052.test", []string{"svc.cr052.test"}), time.Hour)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	leaf := leafFromPEM(t, issued.CertificatePEM)
	if slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) || !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Fatalf("leaf extended key usages = %v, want serverAuth only", leaf.ExtKeyUsage)
	}
}
