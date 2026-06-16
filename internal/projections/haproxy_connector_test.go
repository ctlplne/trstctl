package projections_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/haproxy"
	"trstctl.com/trstctl/internal/connector/haproxy/haproxytest"
	"trstctl.com/trstctl/internal/orchestrator"
)

var (
	hapCert = []byte("-----BEGIN CERTIFICATE-----\nrenewed-leaf\n-----END CERTIFICATE-----\n")
	hapKey  = []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")
)

// TestHAProxyDeploysRenewedCertViaOutbox is the S5.9 AN-6 acceptance: a renewed
// certificate is deployed to HAProxy through the outbox, and redelivery is
// idempotent.
func TestHAProxyDeploysRenewedCertViaOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	const crtPath = "/etc/haproxy/certs/site.pem"
	srv := haproxytest.New(crtPath)
	reg := connector.NewRegistry(func(string) connector.Ops { return srv })
	reg.Register(haproxy.New(crtPath, "/etc/haproxy/haproxy.cfg"))

	payload, err := connector.EncodeDeploy("haproxy", connector.NewDeployment("fe-1", hapCert, hapKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "haproxy-1", Payload: payload,
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
	active := srv.Active()
	if !bytes.Contains(active, hapCert) || !bytes.Contains(active, hapKey) {
		t.Fatal("haproxy is not serving the renewed bundle after outbox delivery")
	}

	if err := reg.Handle(ctx, payload); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	if !bytes.Equal(srv.Active(), active) {
		t.Error("redelivery changed the served bundle")
	}
}
