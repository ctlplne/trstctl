// SPDX-License-Identifier: BUSL-1.1

package kemp_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/kemp"
	"trstctl.com/trstctl/internal/connector/kemp/kemptest"
)

// Readback on a LoadMaster (epic E2) reports which certificate the virtual
// service is bound to, as the device says it, so a relay can tell a binding
// that moved from one that did not.
func TestKempReadbackReportsTheBoundCertificate(t *testing.T) {
	srv := kemptest.New(kempToken)
	defer srv.Close()
	c := kemp.New(srv.URL(), []byte(kempToken))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	if got, err := connector.RunReadback(ctx, c, ops, kempTarget); err != nil || connector.ClassifyReadback(got, "") != connector.ReadbackAbsent {
		t.Fatalf("readback before any deploy = %+v %v, want absent", got, err)
	}
	first := connector.NewDeployment(kempTarget, []byte("-----BEGIN CERTIFICATE-----\nprev\n-----END CERTIFICATE-----\n"), kempKey)
	if _, err := connector.Run(ctx, c, ops, first); err != nil {
		t.Fatal(err)
	}
	got, err := connector.RunReadback(ctx, c, ops, kempTarget)
	if err != nil || connector.ClassifyReadback(got, first.Fingerprint) != connector.ReadbackServing ||
		got.ObjectName != connector.DeployedObjectName(kempTarget+"-trstctl", first.Fingerprint) {
		t.Fatalf("readback after the deploy = %+v %v, want the deployed certificate serving", got, err)
	}
	second := connector.NewDeployment(kempTarget, kempCert, kempKey)
	if _, err := connector.Run(ctx, c, ops, second); err != nil {
		t.Fatal(err)
	}
	if got, _ := connector.RunReadback(ctx, c, ops, kempTarget); connector.ClassifyReadback(got, first.Fingerprint) != connector.ReadbackDiverged {
		t.Fatalf("readback compared with the replaced certificate = %+v, want diverged", got)
	}
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{Target: kempTarget, PredecessorFingerprint: first.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	if got, _ := connector.RunReadback(ctx, c, ops, kempTarget); connector.ClassifyReadback(got, first.Fingerprint) != connector.ReadbackServing {
		t.Fatalf("readback after the rollback = %+v, want the predecessor serving", got)
	}
}
