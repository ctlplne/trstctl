// SPDX-License-Identifier: BUSL-1.1

package fortigate_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/fortigate"
	"trstctl.com/trstctl/internal/connector/fortigate/fortigatetest"
)

// Re-bind rollback (A44). With bind_to configured the connector uploads each
// certificate under a fingerprint-carrying name and points the chosen FortiOS
// setting at it, so the predecessor survives the next deploy and a rollback is
// one PUT of the setting back to it: no material moves.
func TestRollbackRebindsTheAdminServerCertificateToThePredecessor(t *testing.T) {
	firstCert, firstKey := material(t)
	secondCert, secondKey := material(t)
	srv := fortigatetest.New(apiToken)
	defer srv.Close()
	c := fortigate.New(srv.URL(), apiToken, fortigate.WithBindTo(fortigate.BindAdmin))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())

	first := connector.NewDeployment("edge", firstCert, firstKey)
	second := connector.NewDeployment("edge", secondCert, secondKey)
	for _, dep := range []connector.Deployment{first, second} {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("deploy: %v", err)
		}
	}
	firstName := connector.DeployedObjectName("edge", first.Fingerprint)
	secondName := connector.DeployedObjectName("edge", second.Fingerprint)
	if _, ok := srv.Stored(firstName); !ok {
		t.Fatalf("the predecessor %q did not survive the second deploy", firstName)
	}
	if got := srv.Bound("admin-server-cert"); got != secondName {
		t.Fatalf("admin-server-cert = %q, want the second deployment %q", got, secondName)
	}
	puts := srv.Puts()

	if _, err := connector.RunRollback(context.Background(), c, ops, connector.Rollback{Target: "edge", PredecessorFingerprint: first.Fingerprint}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := srv.Bound("admin-server-cert"); got != firstName {
		t.Fatalf("after rollback admin-server-cert = %q, want the predecessor %q", got, firstName)
	}
	if srv.Puts() != puts {
		t.Fatalf("rollback uploaded material: puts %d -> %d", puts, srv.Puts())
	}
	installed, err := connector.RunReadback(context.Background(), c, ops, "edge")
	if err != nil || !installed.Bound || installed.ObjectName != firstName || !strings.HasPrefix(strings.ToLower(first.Fingerprint), installed.Fingerprint) {
		t.Fatalf("readback after rollback = %+v err=%v; want the predecessor bound", installed, err)
	}
	if _, err := connector.RunRollback(context.Background(), c, ops, connector.Rollback{Target: "edge", PredecessorFingerprint: "0000000000000000"}); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback to an object that is not on the appliance = %v, want ErrNoPredecessorInstalled", err)
	}
	if refused := srv.Refused(); len(refused) != 0 {
		t.Fatalf("off-contract calls: %+v", refused)
	}

	// ssl-vpn is the other documented binding.
	vpn := fortigate.New(srv.URL(), apiToken, fortigate.WithBindTo(fortigate.BindSSLVPN))
	t.Cleanup(vpn.Close)
	if _, err := connector.Run(context.Background(), vpn, ops, first); err != nil {
		t.Fatalf("deploy ssl-vpn: %v", err)
	}
	if got := srv.Bound("servercert"); got != firstName {
		t.Fatalf("servercert = %q, want %q", got, firstName)
	}

	// Without a binding the connector keeps the legacy in-place deploy and
	// cannot roll back; it says so instead of answering success.
	legacy := fortigate.New(srv.URL(), apiToken)
	t.Cleanup(legacy.Close)
	if _, err := connector.RunRollback(context.Background(), legacy, ops, connector.Rollback{Target: "edge", PredecessorFingerprint: first.Fingerprint}); !errors.Is(err, connector.ErrRollbackNotConfigured) {
		t.Fatalf("rollback without bind_to = %v, want ErrRollbackNotConfigured", err)
	}
	if _, err := connector.RunReadback(context.Background(), legacy, ops, "edge"); !errors.Is(err, connector.ErrReadbackNotConfigured) {
		t.Fatalf("readback without bind_to = %v, want ErrReadbackNotConfigured", err)
	}
	if _, err := fortigate.ParseBindTo("firewall"); err == nil {
		t.Fatal("an unknown bind_to value was accepted")
	}
}
