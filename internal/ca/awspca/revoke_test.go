// SPDX-License-Identifier: BUSL-1.1

package awspca_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/awspca"
	"trstctl.com/trstctl/internal/ca/awspca/awspcafake"
)

// A164: a revoke with a reason reaches AWS Private CA's RevokeCertificate for
// the issued serial in AWS's colon-separated form; AWS's "already processed"
// on a retry changes nothing.
func TestPluginRevokesThroughAWSPrivateCA(t *testing.T) {
	api, err := awspcafake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	p := awspca.New(awspca.Config{Name: "aws-private-ca", CertificateAuthorityArn: api.CAArn()}, api)
	ctx := context.Background()
	cert, err := p.Issue(ctx, ca.IssueRequest{TenantID: "t1", CSR: awspcaCSR(t, "svc.awspca.test"), DNSNames: []string{"svc.awspca.test"}, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !ca.CanRevoke("awspca") {
		t.Fatal("the capability matrix does not say AWS Private CA can revoke")
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: cert.Serial, ReasonCode: 1}); err != nil {
			t.Fatalf("revoke attempt %d: %v", attempt, err)
		}
		revoked := api.Revocations()
		if len(revoked) != 1 {
			t.Fatalf("after attempt %d AWS revoked %v; want exactly the issued certificate", attempt, revoked)
		}
		for _, reason := range revoked {
			if reason != "KEY_COMPROMISE" {
				t.Fatalf("AWS recorded %q; want KEY_COMPROMISE", reason)
			}
		}
	}
	if err := ca.RevokeThrough(ctx, p, ca.RevokeRequest{TenantID: "t1", Serial: "abcdef0123", ReasonCode: 1}); err == nil {
		t.Fatal("revoking a serial AWS never issued reported success")
	}
}
