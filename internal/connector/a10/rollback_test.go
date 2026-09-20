// SPDX-License-Identifier: BUSL-1.1

package a10_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/a10"
	"trstctl.com/trstctl/internal/connector/a10/a10test"
)

// Rollback on a Thunder client-SSL template (epic D4). The template name is
// stable across deploy and rollback so virtual ports bound to it are untouched;
// what moves is which uploaded file pair the template resolves to.

const a10Template = "payments-client-ssl"

var a10Predecessor = []byte("-----BEGIN CERTIFICATE-----\na10-previous\n-----END CERTIFICATE-----\n")

func TestA10RollbackRepointsTheTemplateAtThePredecessor(t *testing.T) {
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
	if _, err := connector.Run(ctx, c, ops, connector.NewDeployment(a10Template, a10Cert, a10Key)); err != nil {
		t.Fatalf("second deploy: %v", err)
	}
	if b, _ := srv.Binding(a10Template); !bytes.Equal(b.Certificate, a10Cert) {
		t.Fatal("the second deploy did not take effect")
	}

	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: a10Template, PredecessorFingerprint: first.Fingerprint,
	}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	b, ok := srv.Binding(a10Template)
	if !ok {
		t.Fatal("template disappeared")
	}
	if !bytes.Equal(b.Certificate, a10Predecessor) {
		t.Errorf("after rollback the template serves %q; want the predecessor — a rollback "+
			"that returns nil without re-pointing the template is exactly the memo-only "+
			"receipt this epic removes", b.Certificate)
	}
}

func TestA10RollbackRefusesWhenThePredecessorIsGone(t *testing.T) {
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
	if _, err := connector.Run(ctx, c, ops, connector.NewDeployment(a10Template, a10Cert, a10Key)); err != nil {
		t.Fatalf("second deploy: %v", err)
	}
	srv.RemoveCert(connector.DeployedObjectName(a10Template, first.Fingerprint) + ".crt")

	_, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: a10Template, PredecessorFingerprint: first.Fingerprint,
	})
	if !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("error = %v; want ErrNoPredecessorInstalled", err)
	}
	if b, _ := srv.Binding(a10Template); !bytes.Equal(b.Certificate, a10Cert) {
		t.Error("a failed rollback changed what the template serves")
	}
}

func TestA10IsInTheRollbackCensus(t *testing.T) {
	if !connector.CanRollback("a10") {
		t.Error("a10 implements Rollbacker but is missing from the rollback census")
	}
	var _ connector.Rollbacker = (*a10.Connector)(nil)
}
