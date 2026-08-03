// SPDX-License-Identifier: MPL-2.0

package f5_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
)

// Rollback as executed re-bind (epic D4).
//
// The scenario is the one that costs money: a certificate is deployed, it is
// wrong, and traffic is failing right now. What an operator needs is not a
// receipt saying somebody intended a rollback — it is the listener serving the
// previous certificate again, without anybody logging into the appliance.

var predecessorCert = []byte("-----BEGIN CERTIFICATE-----\nf5-previous\n-----END CERTIFICATE-----\n")

// The whole loop: deploy, deploy again, roll back, and the profile is serving
// the first certificate.
func TestRollbackRebindsTheProfileToThePredecessor(t *testing.T) {
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

	// The predecessor survived the second deploy. Before D4 it did not: both
	// deployments installed under the same name and the second destroyed the
	// only object a rollback could have used.
	firstBase := connector.DeployedObjectName(profile, first.Fingerprint)
	if !srv.InstalledCert(firstBase + ".crt") {
		t.Fatal("the second deploy overwrote the predecessor object; there is nothing to roll back to")
	}
	secondBase := connector.DeployedObjectName(profile, second.Fingerprint)
	if firstBase == secondBase {
		t.Fatal("two different certificates produced the same object name")
	}
	if chain, _ := srv.Profile(profile); chain.Cert != secondBase+".crt" {
		t.Fatalf("profile is bound to %q, want the second deploy %q", chain.Cert, secondBase+".crt")
	}

	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: "app", PredecessorFingerprint: first.Fingerprint, Reason: "wrong SAN",
	}); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	chain, ok := srv.Profile(profile)
	if !ok {
		t.Fatal("profile disappeared")
	}
	if chain.Cert != firstBase+".crt" || chain.Key != firstBase+".key" {
		t.Errorf("after rollback the profile is bound to %+v; want the predecessor %q — "+
			"a rollback that returns nil without re-pointing the listener is the failure "+
			"this whole epic exists to remove", chain, firstBase+".crt")
	}
	// Nothing was uploaded to perform the rollback. That is the property that
	// makes it possible at all: the control plane holds no subject key.
	if _, uploaded := srv.Uploaded(firstBase + ".crt"); !uploaded {
		t.Fatal("test setup: the predecessor should have been uploaded by the first deploy")
	}
}

// A rollback whose predecessor is not on the appliance must FAIL.
//
// This is the case where a silent success is actively dangerous: the operator
// is told the bad certificate has stopped serving traffic, and it has not.
func TestRollbackRefusesWhenThePredecessorIsGone(t *testing.T) {
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
	// Somebody tidied the appliance.
	srv.RemoveCert(connector.DeployedObjectName(profile, first.Fingerprint) + ".crt")

	_, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: "app", PredecessorFingerprint: first.Fingerprint,
	})
	if err == nil {
		t.Fatal("rollback reported success with no predecessor installed")
	}
	if !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Errorf("error = %v; want ErrNoPredecessorInstalled — the operator response to "+
			"'there is nothing to roll back to' differs from a network failure, and "+
			"a generic error makes them retry something that cannot succeed", err)
	}
	// The profile is untouched: a failed rollback must not leave the listener
	// pointing at a half-applied state.
	secondBase := connector.DeployedObjectName(profile, second.Fingerprint)
	if chain, _ := srv.Profile(profile); chain.Cert != secondBase+".crt" {
		t.Errorf("a failed rollback changed the binding to %+v", chain)
	}
}

// An empty predecessor fingerprint is refused before any call is made.
//
// A first deployment has no predecessor, and asking the appliance about an
// object named after nothing would either 404 confusingly or, worse, match
// something.
func TestRollbackRefusesWithoutAPredecessor(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()
	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass)))
	ops := connector.NewHTTPOps(srv.Client())

	before := srv.Calls()
	_, err := connector.RunRollback(context.Background(), c, ops, connector.Rollback{Target: "app"})
	if !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("error = %v; want ErrNoPredecessorInstalled", err)
	}
	if srv.Calls() != before {
		t.Error("a rollback with no predecessor reached the appliance; it should be refused locally")
	}
}

// The census must match the interface: f5 claims rollback and implements it.
func TestF5IsInTheRollbackCensus(t *testing.T) {
	if !connector.CanRollback("f5") {
		t.Error("f5 implements Rollbacker but is missing from the rollback census")
	}
	var _ connector.Rollbacker = (*f5.Connector)(nil)
}
