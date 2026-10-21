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

func TestNetScalerTakedownRemovesUnboundFilesAndRefusesTheBoundOnes(t *testing.T) {
	srv := netscalertest.New(user, pass)
	defer srv.Close()
	c := netscaler.New(srv.URL(), user, []byte(pass))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	first := connector.NewDeployment(certkey, nsPredecessor, sampleKey)
	if _, err := connector.Run(ctx, c, ops, first); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	second := connector.NewDeployment(certkey, sampleCert, sampleKey)
	if _, err := connector.Run(ctx, c, ops, second); err != nil {
		t.Fatalf("second deploy: %v", err)
	}
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: certkey, Fingerprint: second.Fingerprint}); !errors.Is(err, connector.ErrTakedownObjectBound) {
		t.Fatalf("takedown of the bound files = %v, want ErrTakedownObjectBound", err)
	}
	firstBase := connector.DeployedObjectName(certkey, first.Fingerprint)
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: certkey, Fingerprint: first.Fingerprint}); err != nil {
		t.Fatalf("takedown of the predecessor: %v", err)
	}
	for _, name := range []string{firstBase + ".crt", firstBase + ".key"} {
		if _, ok := srv.File(name); ok {
			t.Fatalf("%s survived the takedown", name)
		}
	}
	if srv.OpenSessions() != 0 {
		t.Fatalf("takedown left %d NITRO sessions open", srv.OpenSessions())
	}
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: certkey, Fingerprint: first.Fingerprint}); !errors.Is(err, connector.ErrTakedownNotInstalled) {
		t.Fatalf("second takedown = %v, want ErrTakedownNotInstalled", err)
	}
}
