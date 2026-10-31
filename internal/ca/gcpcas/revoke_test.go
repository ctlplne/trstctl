// SPDX-License-Identifier: BUSL-1.1

package gcpcas_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/gcpcas"
	"trstctl.com/trstctl/internal/ca/gcpcas/gcpcasfake"
)

// A164: a revoke with a reason reaches CAS for the pool's certificate with the
// issued serial, and retrying it changes nothing.
func TestPluginRevokesThroughCAS(t *testing.T) {
	api, err := gcpcasfake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	p := gcpcas.New(gcpcas.Config{Name: "gcp-cas", CaPool: api.CaPool()}, api)
	ctx := context.Background()
	cert, err := p.Issue(ctx, ca.IssueRequest{TenantID: "t1", CSR: gcpcasCSR(t, "svc.gcpcas.test"), DNSNames: []string{"svc.gcpcas.test"}, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !ca.CanRevoke("gcpcas") {
		t.Fatal("the capability matrix does not say Google CAS can revoke")
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: cert.Serial, ReasonCode: 4}); err != nil {
			t.Fatalf("revoke attempt %d: %v", attempt, err)
		}
		revoked := api.Revocations()
		if len(revoked) != 1 {
			t.Fatalf("after attempt %d CAS revoked %v; want exactly the issued certificate", attempt, revoked)
		}
		for _, reason := range revoked {
			if reason != "SUPERSEDED" {
				t.Fatalf("CAS recorded %q; want SUPERSEDED", reason)
			}
		}
	}
	if err := ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: "abc123", ReasonCode: 4}); err == nil {
		t.Fatal("revoking a serial CAS never issued reported success")
	}
}
