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

func TestA10RollbackFallsBackToTheLegacyFilesOnlyWhenAllowed(t *testing.T) {
	srv := a10test.New("admin", "s3cret")
	defer srv.Close()
	c := a10.New(srv.URL(), "admin", []byte("s3cret"))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	if _, err := connector.Run(ctx, c, ops, connector.Deployment{Target: a10Template, CertPEM: a10Predecessor, KeyPEM: a10Key}); err != nil {
		t.Fatalf("legacy deploy: %v", err)
	}
	if _, err := connector.Run(ctx, c, ops, connector.NewDeployment(a10Template, a10Cert, a10Key)); err != nil {
		t.Fatalf("current deploy: %v", err)
	}
	predecessor := connector.NewDeployment(a10Template, a10Predecessor, a10Key).Fingerprint
	if _, _, err := connector.RunRollbackWithResult(ctx, c, ops, connector.Rollback{Target: a10Template, PredecessorFingerprint: predecessor}); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback without the legacy fallback = %v", err)
	}
	_, result, err := connector.RunRollbackWithResult(ctx, c, ops, connector.Rollback{Target: a10Template, PredecessorFingerprint: predecessor, AllowLegacyObject: true})
	if err != nil || !result.LegacyObject {
		t.Fatalf("legacy rollback = %+v err=%v", result, err)
	}
	if b, _ := srv.Binding(a10Template); b.CertFile != a10Template+".crt" {
		t.Fatalf("template bound to %+v, want the legacy files", b)
	}
}
