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

const (
	kempToken  = "token"
	kempTarget = "vs-payments-443"
)

// Rollback as executed re-bind on a LoadMaster (epic D4). Same contract as
// every other rollback-capable family, which is the point of putting rollback
// on the connector interface rather than writing it per appliance.

func TestKempRollbackRebindsTheVirtualServiceToThePredecessor(t *testing.T) {
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

	firstName := connector.DeployedObjectName(kempTarget+"-trstctl", first.Fingerprint)
	secondName := connector.DeployedObjectName(kempTarget+"-trstctl", second.Fingerprint)
	if bound, _ := srv.BoundCertName(kempTarget); bound != secondName {
		t.Fatalf("virtual service bound to %q, want the second deploy %q", bound, secondName)
	}

	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: kempTarget, PredecessorFingerprint: first.Fingerprint,
	}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	bound, ok := srv.BoundCertName(kempTarget)
	if !ok || bound != firstName {
		t.Errorf("after rollback the virtual service is bound to %q; want the predecessor %q", bound, firstName)
	}
}

func TestKempRollbackRefusesWhenThePredecessorIsGone(t *testing.T) {
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
	if _, err := connector.Run(ctx, c, ops, connector.NewDeployment(kempTarget, kempCert, kempKey)); err != nil {
		t.Fatalf("second deploy: %v", err)
	}
	srv.RemoveCert(connector.DeployedObjectName(kempTarget+"-trstctl", first.Fingerprint))

	_, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: kempTarget, PredecessorFingerprint: first.Fingerprint,
	})
	if !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("error = %v; want ErrNoPredecessorInstalled — reporting success here tells an "+
			"operator a bad certificate stopped serving traffic when it did not", err)
	}
}

func TestKempIsInTheRollbackCensus(t *testing.T) {
	if !connector.CanRollback("kemp") {
		t.Error("kemp implements Rollbacker but is missing from the rollback census")
	}
	var _ connector.Rollbacker = (*kemp.Connector)(nil)
}
