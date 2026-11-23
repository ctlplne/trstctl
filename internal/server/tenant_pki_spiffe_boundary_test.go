// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// The Workload API has a tenant CA. A tenant-controlled request to the shared
// platform issuer must not produce a second certificate for that trust domain.
func TestCR042PlatformIssuerRefusesSPIFFEWorkloadIdentity(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	registerServedTenantID(t, h, "66666666-6666-4666-8666-666666666666", "neighbor tenant")
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "other-tenant.svc.test",
		DNSNames:   []string{"other-tenant.svc.test"},
		URIs:       []string{"spiffe://served.test/other-tenant/workload"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := h.srv.IssueLeafWithProfile(context.Background(), csr, time.Hour, crypto.LeafProfile{})
	if err == nil || !strings.Contains(err.Error(), "SPIFFE") || len(leaf) != 0 {
		t.Fatalf("platform CA signed a workload identity: leaf length=%d, error=%v", len(leaf), err)
	}
}
