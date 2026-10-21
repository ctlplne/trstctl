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

func TestKempRollbackFallsBackToTheLegacyCertificateOnlyWhenAllowed(t *testing.T) {
	srv := kemptest.New(kempToken)
	defer srv.Close()
	c := kemp.New(srv.URL(), []byte(kempToken))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	prev := []byte("-----BEGIN CERTIFICATE-----\nprev\n-----END CERTIFICATE-----\n")
	if _, err := connector.Run(ctx, c, ops, connector.Deployment{Target: kempTarget, CertPEM: prev, KeyPEM: kempKey}); err != nil {
		t.Fatalf("legacy deploy: %v", err)
	}
	if _, err := connector.Run(ctx, c, ops, connector.NewDeployment(kempTarget, kempCert, kempKey)); err != nil {
		t.Fatalf("current deploy: %v", err)
	}
	predecessor := connector.NewDeployment(kempTarget, prev, kempKey).Fingerprint
	if _, _, err := connector.RunRollbackWithResult(ctx, c, ops, connector.Rollback{Target: kempTarget, PredecessorFingerprint: predecessor}); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback without the legacy fallback = %v", err)
	}
	_, result, err := connector.RunRollbackWithResult(ctx, c, ops, connector.Rollback{Target: kempTarget, PredecessorFingerprint: predecessor, AllowLegacyObject: true})
	if err != nil || !result.LegacyObject {
		t.Fatalf("legacy rollback = %+v err=%v", result, err)
	}
	if bound, _ := srv.BoundCertName(kempTarget); bound != kempTarget+"-trstctl" {
		t.Fatalf("bound to %q, want the legacy certificate", bound)
	}
}
