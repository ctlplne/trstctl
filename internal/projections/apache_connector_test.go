package projections_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/apache"
	"trstctl.com/trstctl/internal/connector/apache/apachetest"
	"trstctl.com/trstctl/internal/orchestrator"
)

var (
	apCert = []byte("-----BEGIN CERTIFICATE-----\nrenewed-leaf\n-----END CERTIFICATE-----\n")
	apKey  = []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")
)

// TestApacheDeploysRenewedCertViaOutbox is the S5.7 AN-6 acceptance: a renewed
// certificate is deployed to Apache through the outbox, and redelivery is
// idempotent.
func TestApacheDeploysRenewedCertViaOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	const certPath = "/etc/apache2/tls/site.crt"
	srv := apachetest.New(certPath)
	reg := connector.NewRegistry(func(string) connector.Ops { return srv })
	reg.Register(apache.New(certPath, "/etc/apache2/tls/site.key"))

	payload, err := connector.EncodeDeploy("apache", connector.NewDeployment("web-1", apCert, apKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "apache-1", Payload: payload,
		})
		return e
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	handler := orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		return reg.Handle(ctx, m.Payload)
	})
	if n, err := ob.Dispatch(ctx, handler); err != nil || n != 1 {
		t.Fatalf("Dispatch n=%d err=%v, want 1", n, err)
	}
	if !bytes.Equal(srv.Active(), apCert) {
		t.Fatal("apache is not serving the renewed certificate after outbox delivery")
	}

	if err := reg.Handle(ctx, payload); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	if !bytes.Equal(srv.Active(), apCert) {
		t.Error("redelivery changed the served certificate")
	}
}
