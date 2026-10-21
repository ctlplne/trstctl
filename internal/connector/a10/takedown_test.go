// SPDX-License-Identifier: BUSL-1.1

package a10_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/a10"
	"trstctl.com/trstctl/internal/connector/a10/a10test"
)

func TestA10TakedownRemovesUnboundFilesAndRefusesTheBoundOnes(t *testing.T) {
	srv := a10test.New("admin", "s3cret")
	defer srv.Close()
	c := a10.New(srv.URL(), "admin", []byte("s3cret"))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	first := connector.NewDeployment(a10Template, a10Predecessor, a10Key)
	if _, err := connector.Run(ctx, c, ops, first); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	second := connector.NewDeployment(a10Template, a10Cert, a10Key)
	if _, err := connector.Run(ctx, c, ops, second); err != nil {
		t.Fatalf("second deploy: %v", err)
	}
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: a10Template, Fingerprint: second.Fingerprint}); !errors.Is(err, connector.ErrTakedownObjectBound) {
		t.Fatalf("takedown of the bound files = %v, want ErrTakedownObjectBound", err)
	}
	firstBase := connector.DeployedObjectName(a10Template, first.Fingerprint)
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: a10Template, Fingerprint: first.Fingerprint}); err != nil {
		t.Fatalf("takedown of the predecessor: %v", err)
	}
	if srv.HasFile("ssl-cert", firstBase+".crt") || srv.HasFile("ssl-key", firstBase+".key") {
		t.Fatal("predecessor files survived the takedown")
	}
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: a10Template, Fingerprint: first.Fingerprint}); !errors.Is(err, connector.ErrTakedownNotInstalled) {
		t.Fatalf("second takedown = %v, want ErrTakedownNotInstalled", err)
	}
}
