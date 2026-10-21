// SPDX-License-Identifier: BUSL-1.1

package f5_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
)

// A43: the bound object is refused, the unbound predecessor's cert and key
// objects are deleted, and a second takedown reports nothing installed.
func TestTakedownRemovesUnboundObjectsAndRefusesTheBoundOne(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()
	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass)))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	first := connector.NewDeployment("app", predecessorCert, sampleKey)
	if _, err := connector.Run(ctx, c, ops, first); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	second := connector.NewDeployment("app", sampleCert, sampleKey)
	if _, err := connector.Run(ctx, c, ops, second); err != nil {
		t.Fatalf("second deploy: %v", err)
	}
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: profile, Fingerprint: second.Fingerprint}); !errors.Is(err, connector.ErrTakedownObjectBound) {
		t.Fatalf("takedown of the bound object = %v, want ErrTakedownObjectBound", err)
	}
	firstBase := connector.DeployedObjectName(profile, first.Fingerprint)
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: profile, Fingerprint: first.Fingerprint}); err != nil {
		t.Fatalf("takedown of the predecessor: %v", err)
	}
	if srv.InstalledCert(firstBase+".crt") || srv.InstalledKey(firstBase+".key") {
		t.Fatal("predecessor objects survived the takedown")
	}
	secondBase := connector.DeployedObjectName(profile, second.Fingerprint)
	if !srv.InstalledCert(secondBase+".crt") || !srv.InstalledKey(secondBase+".key") {
		t.Fatal("the bound successor was removed")
	}
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: profile, Fingerprint: first.Fingerprint}); !errors.Is(err, connector.ErrTakedownNotInstalled) {
		t.Fatalf("second takedown = %v, want ErrTakedownNotInstalled", err)
	}
}
