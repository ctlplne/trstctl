// SPDX-License-Identifier: BUSL-1.1

package kemp_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/kemp"
	"trstctl.com/trstctl/internal/connector/kemp/kemptest"
)

func TestKempTakedownRemovesUnboundCertificatesAndRefusesTheBoundOne(t *testing.T) {
	srv := kemptest.New(kempToken)
	defer srv.Close()
	c := kemp.New(srv.URL(), []byte(kempToken))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	first := connector.NewDeployment(kempTarget, []byte("-----BEGIN CERTIFICATE-----\nprev\n-----END CERTIFICATE-----\n"), kempKey)
	if _, err := connector.Run(ctx, c, ops, first); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	second := connector.NewDeployment(kempTarget, kempCert, kempKey)
	if _, err := connector.Run(ctx, c, ops, second); err != nil {
		t.Fatalf("second deploy: %v", err)
	}
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: kempTarget, Fingerprint: second.Fingerprint}); !errors.Is(err, connector.ErrTakedownObjectBound) {
		t.Fatalf("takedown of the bound certificate = %v, want ErrTakedownObjectBound", err)
	}
	firstName := connector.DeployedObjectName(kempTarget+"-trstctl", first.Fingerprint)
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: kempTarget, Fingerprint: first.Fingerprint}); err != nil {
		t.Fatalf("takedown of the predecessor: %v", err)
	}
	if srv.HasCert(firstName) {
		t.Fatal("predecessor certificate survived the takedown")
	}
	if bound, _ := srv.BoundCertName(kempTarget); bound != connector.DeployedObjectName(kempTarget+"-trstctl", second.Fingerprint) {
		t.Fatalf("binding changed to %q", bound)
	}
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: kempTarget, Fingerprint: first.Fingerprint}); !errors.Is(err, connector.ErrTakedownNotInstalled) {
		t.Fatalf("second takedown = %v, want ErrTakedownNotInstalled", err)
	}
}
