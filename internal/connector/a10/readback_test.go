// SPDX-License-Identifier: BUSL-1.1

package a10_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/a10"
	"trstctl.com/trstctl/internal/connector/a10/a10test"
)

// Readback on a Thunder (epic E2) reports the certificate file the client-SSL
// template names, as the device says it.
func TestA10ReadbackReportsTheTemplateCertificate(t *testing.T) {
	srv := a10test.New("admin", "s3cret")
	defer srv.Close()
	c := a10.New(srv.URL(), "admin", []byte("s3cret"))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	if got, err := connector.RunReadback(ctx, c, ops, a10Template); err != nil || connector.ClassifyReadback(got, "") != connector.ReadbackAbsent {
		t.Fatalf("readback of a template that does not exist = %+v %v, want absent", got, err)
	}
	first := connector.NewDeployment(a10Template, a10Predecessor, a10Key)
	if _, err := connector.Run(ctx, c, ops, first); err != nil {
		t.Fatal(err)
	}
	got, err := connector.RunReadback(ctx, c, ops, a10Template)
	if err != nil || connector.ClassifyReadback(got, first.Fingerprint) != connector.ReadbackServing ||
		got.ObjectName != connector.DeployedObjectName(a10Template, first.Fingerprint)+".crt" {
		t.Fatalf("readback after the deploy = %+v %v, want the deployed certificate serving", got, err)
	}
	second := connector.NewDeployment(a10Template, a10Cert, a10Key)
	if _, err := connector.Run(ctx, c, ops, second); err != nil {
		t.Fatal(err)
	}
	if got, _ := connector.RunReadback(ctx, c, ops, a10Template); connector.ClassifyReadback(got, first.Fingerprint) != connector.ReadbackDiverged {
		t.Fatalf("readback compared with the replaced certificate = %+v, want diverged", got)
	}
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{Target: a10Template, PredecessorFingerprint: first.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	if got, _ := connector.RunReadback(ctx, c, ops, a10Template); connector.ClassifyReadback(got, first.Fingerprint) != connector.ReadbackServing {
		t.Fatalf("readback after the rollback = %+v, want the predecessor serving", got)
	}
}
