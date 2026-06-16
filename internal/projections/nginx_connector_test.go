package projections_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/nginx"
	"trstctl.com/trstctl/internal/connector/nginx/nginxtest"
	"trstctl.com/trstctl/internal/orchestrator"
)

var (
	ngxCert = []byte("-----BEGIN CERTIFICATE-----\nrenewed-leaf\n-----END CERTIFICATE-----\n")
	ngxKey  = []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")
)

// TestNginxDeploysRenewedCertViaOutbox is the S5.6 AN-6 acceptance: a renewed
// certificate is deployed to NGINX through the outbox, and redelivery is
// idempotent.
func TestNginxDeploysRenewedCertViaOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	const certPath = "/etc/nginx/tls/site.crt"
	srv := nginxtest.New(certPath)
	reg := connector.NewRegistry(func(string) connector.Ops { return srv })
	reg.Register(nginx.New(certPath, "/etc/nginx/tls/site.key"))

	payload, err := connector.EncodeDeploy("nginx", connector.NewDeployment("web-1", ngxCert, ngxKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "nginx-1", Payload: payload,
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
	if !bytes.Equal(srv.Active(), ngxCert) {
		t.Fatal("nginx is not serving the renewed certificate after outbox delivery")
	}

	// At-least-once redelivery is idempotent.
	if err := reg.Handle(ctx, payload); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	if !bytes.Equal(srv.Active(), ngxCert) {
		t.Error("redelivery changed the served certificate")
	}
}
