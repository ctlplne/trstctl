// SPDX-License-Identifier: BUSL-1.1

package netscaler_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/netscaler"
	"trstctl.com/trstctl/internal/connector/netscaler/netscalertest"
)

// Readback on a NetScaler (epic E2) reports the certificate file the certkey
// resolves to and whether any SSL virtual server uses the certkey: a certkey
// no vserver is bound to is installed and serves nothing.
func TestNetScalerReadbackReportsTheCertkeyAndItsVserverBinding(t *testing.T) {
	srv := netscalertest.New(user, pass)
	defer srv.Close()
	c := netscaler.New(srv.URL(), user, []byte(pass))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	if got, err := connector.RunReadback(ctx, c, ops, certkey); err != nil || connector.ClassifyReadback(got, "") != connector.ReadbackAbsent {
		t.Fatalf("readback of a certkey that does not exist = %+v %v, want absent", got, err)
	}
	first := connector.NewDeployment(certkey, nsPredecessor, sampleKey)
	if _, err := connector.Run(ctx, c, ops, first); err != nil {
		t.Fatal(err)
	}
	got, err := connector.RunReadback(ctx, c, ops, certkey)
	if err != nil || connector.ClassifyReadback(got, first.Fingerprint) != connector.ReadbackInstalledNotBound ||
		got.ObjectName != connector.DeployedObjectName(certkey, first.Fingerprint)+".crt" {
		t.Fatalf("readback with no vserver bound = %+v %v, want installed but not bound", got, err)
	}
	srv.BindVServer(certkey, "vs-web-443")
	if got, _ := connector.RunReadback(ctx, c, ops, certkey); connector.ClassifyReadback(got, first.Fingerprint) != connector.ReadbackServing {
		t.Fatalf("readback once a vserver uses the certkey = %+v, want serving", got)
	}
	second := connector.NewDeployment(certkey, sampleCert, sampleKey)
	if _, err := connector.Run(ctx, c, ops, second); err != nil {
		t.Fatal(err)
	}
	if got, _ := connector.RunReadback(ctx, c, ops, certkey); connector.ClassifyReadback(got, first.Fingerprint) != connector.ReadbackDiverged ||
		connector.ClassifyReadback(got, second.Fingerprint) != connector.ReadbackServing {
		t.Fatalf("readback after a second deploy = %+v, want the second certificate serving", got)
	}
	if srv.OpenSessions() != 0 {
		t.Fatalf("readback left %d NITRO sessions open", srv.OpenSessions())
	}
}
