// SPDX-License-Identifier: BUSL-1.1

package smallstep_test

import (
	"context"
	"math/big"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/smallstep"
	"trstctl.com/trstctl/internal/ca/smallstep/smallstepfake"
)

// A164: a revoke with a reason reaches step-ca for the issued serial under a
// token whose subject is that serial, and retrying it changes nothing.
func TestPluginRevokesThroughStepCA(t *testing.T) {
	srv, err := smallstepfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	p := smallstep.New(config(srv), smallstep.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	ctx := context.Background()
	cert, err := p.Issue(ctx, ca.IssueRequest{
		TenantID: "t1", CSR: smallstepCSR(t, "svc.smallstep.test"), DNSNames: []string{"svc.smallstep.test"}, TTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !ca.CanRevoke("smallstep") {
		t.Fatal("the capability matrix does not say step-ca can revoke")
	}
	decimal, ok := new(big.Int).SetString(cert.Serial, 16)
	if !ok {
		t.Fatalf("issued serial %q is not hex", cert.Serial)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: cert.Serial, ReasonCode: 1}); err != nil {
			t.Fatalf("revoke attempt %d: %v", attempt, err)
		}
		if reason, revoked := srv.Revoked(decimal.String()); !revoked || reason != 1 {
			t.Fatalf("after attempt %d step-ca has serial %s revoked=%t reason=%d; want keyCompromise", attempt, decimal, revoked, reason)
		}
	}
	if err := ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: "not-hex", ReasonCode: 1}); err == nil {
		t.Fatal("a serial that is not hex reached step-ca")
	}
}
