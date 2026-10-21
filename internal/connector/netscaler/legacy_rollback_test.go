// SPDX-License-Identifier: BUSL-1.1

package netscaler_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/netscaler"
	"trstctl.com/trstctl/internal/connector/netscaler/netscalertest"
)

func TestNetScalerRollbackFallsBackToTheLegacyFilesOnlyWhenAllowed(t *testing.T) {
	srv := netscalertest.New(user, pass)
	defer srv.Close()
	c := netscaler.New(srv.URL(), user, []byte(pass))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	if _, err := connector.Run(ctx, c, ops, connector.Deployment{Target: certkey, CertPEM: nsPredecessor, KeyPEM: sampleKey}); err != nil {
		t.Fatalf("legacy deploy: %v", err)
	}
	if _, err := connector.Run(ctx, c, ops, connector.NewDeployment(certkey, sampleCert, sampleKey)); err != nil {
		t.Fatalf("current deploy: %v", err)
	}
	predecessor := connector.NewDeployment(certkey, nsPredecessor, sampleKey).Fingerprint
	if _, _, err := connector.RunRollbackWithResult(ctx, c, ops, connector.Rollback{Target: certkey, PredecessorFingerprint: predecessor}); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback without the legacy fallback = %v", err)
	}
	_, result, err := connector.RunRollbackWithResult(ctx, c, ops, connector.Rollback{Target: certkey, PredecessorFingerprint: predecessor, AllowLegacyObject: true})
	if err != nil || !result.LegacyObject {
		t.Fatalf("legacy rollback = %+v err=%v", result, err)
	}
	if b, _ := srv.Binding(certkey); b.Cert != certkey+".crt" || b.Key != certkey+".key" {
		t.Fatalf("certkey bound to %+v, want the legacy files", b)
	}
	if srv.OpenSessions() != 0 {
		t.Fatalf("%d NITRO sessions left open", srv.OpenSessions())
	}
}
