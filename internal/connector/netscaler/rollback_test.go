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

// Rollback on a NetScaler (epic D4).
//
// The certkey object keeps its name across deploys and rollbacks, which is what
// makes this safe: every vserver bound to that certkey is untouched. What moves
// is the file pair the certkey resolves to — precisely the thing a deploy
// changed.

var nsPredecessor = []byte("-----BEGIN CERTIFICATE-----\nns-previous\n-----END CERTIFICATE-----\n")

func TestNetScalerRollbackRepointsTheCertkeyAtThePredecessorFiles(t *testing.T) {
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

	firstBase := connector.DeployedObjectName(certkey, first.Fingerprint)
	if _, ok := srv.File(firstBase + ".crt"); !ok {
		t.Fatal("the second deploy overwrote the predecessor file; nothing to roll back to")
	}

	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: certkey, PredecessorFingerprint: first.Fingerprint,
	}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	b, ok := srv.Binding(certkey)
	if !ok || b.Cert != firstBase+".crt" || b.Key != firstBase+".key" {
		t.Errorf("after rollback the certkey resolves to %+v; want the predecessor %q", b, firstBase+".crt")
	}
}

func TestNetScalerRollbackRefusesWhenThePredecessorFileIsGone(t *testing.T) {
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
	firstBase := connector.DeployedObjectName(certkey, first.Fingerprint)
	srv.RemoveFile(firstBase + ".crt")

	_, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: certkey, PredecessorFingerprint: first.Fingerprint,
	})
	if !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("error = %v; want ErrNoPredecessorInstalled", err)
	}
	// And the certkey still resolves to the current deployment: a failed
	// rollback must not leave the certkey pointing at a file that is not there,
	// which would take the listener down rather than restore it.
	secondBase := connector.DeployedObjectName(certkey, second.Fingerprint)
	if b, _ := srv.Binding(certkey); b.Cert != secondBase+".crt" {
		t.Errorf("a failed rollback changed the certkey to %+v", b)
	}
}

func TestNetScalerIsInTheRollbackCensus(t *testing.T) {
	if !connector.CanRollback("netscaler") {
		t.Error("netscaler implements Rollbacker but is missing from the rollback census")
	}
	var _ connector.Rollbacker = (*netscaler.Connector)(nil)
}

// A transport failure must never be reported as "the predecessor is gone".
//
// The two answers send an operator to opposite places: "gone" means reissue,
// because no retry can help; a transport failure means try again. Classifying on
// the text of an error made them collide — a connection failure carries the
// request URL, the URL now carries a fingerprint-derived object name, and a
// fingerprint whose hex happens to contain "404" turned an unreachable appliance
// into a definitive, non-retryable verdict. Roughly one in four hundred.
func TestNetScalerTransportFailureIsNotReportedAsPredecessorGone(t *testing.T) {
	srv := netscalertest.New(user, pass)
	c := netscaler.New(srv.URL(), user, []byte(pass))
	ops := connector.NewHTTPOps(srv.Client())
	// Close the appliance: every call now fails at the transport, and the URL in
	// the error carries an object name containing the digits 404.
	srv.Close()

	_, err := connector.RunRollback(context.Background(), c, ops, connector.Rollback{
		Target: certkey,
		// A fingerprint whose first 12 hex characters contain "404".
		PredecessorFingerprint: "404decafbad0feedfacecafebeefdeadbeefcafefeedfacecafebeefdeadbeef",
	})
	if err == nil {
		t.Fatal("a rollback against an unreachable appliance reported success")
	}
	if errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Errorf("an unreachable appliance was reported as ErrNoPredecessorInstalled (%v); "+
			"the operator is told to reissue when they should retry", err)
	}
}
