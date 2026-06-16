package projections_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/gcpcm"
	"trstctl.com/trstctl/internal/connector/gcpcm/gcpcmtest"
	"trstctl.com/trstctl/internal/orchestrator"
)

var (
	gcpCert = []byte("-----BEGIN CERTIFICATE-----\nrenewed-leaf\n-----END CERTIFICATE-----\n")
	gcpKey  = []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")
)

// TestGCPCMDeploysRenewedCertViaOutbox is the S5.13 AN-6 acceptance: a renewed
// certificate is applied to a GCP Certificate Manager self-managed certificate
// through the outbox, and redelivery is idempotent.
func TestGCPCMDeploysRenewedCertViaOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	const (
		tok    = "ya29.bearer"
		certID = "web-prod"
	)
	srv := gcpcmtest.New(tok)
	defer srv.Close()

	reg := connector.NewRegistry(func(string) connector.Ops {
		return connector.NewHTTPOps(srv.Client())
	})
	reg.Register(gcpcm.New("my-project", "global", gcpcm.StaticToken(tok),
		gcpcm.WithEndpoint(srv.URL()), gcpcm.WithPollInterval(0)))

	payload, err := connector.EncodeDeploy("gcp-certificate-manager", connector.NewDeployment(certID, gcpCert, gcpKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "gcpcm-1", Payload: payload,
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

	got, ok := srv.Imported(certID)
	if !ok || got.PEMCertificate != string(gcpCert) || got.PEMPrivateKey != string(gcpKey) {
		t.Fatalf("Certificate Manager did not receive the renewed credential after outbox delivery")
	}

	if err := reg.Handle(ctx, payload); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	got2, _ := srv.Imported(certID)
	if got2 != got {
		t.Error("redelivery changed the applied certificate")
	}
}
