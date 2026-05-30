package projections_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"certctl.io/certctl/internal/connector"
	"certctl.io/certctl/internal/connector/azurekv"
	"certctl.io/certctl/internal/connector/azurekv/azurekvtest"
	"certctl.io/certctl/internal/orchestrator"
)

var (
	kvCert = []byte("-----BEGIN CERTIFICATE-----\nrenewed-leaf\n-----END CERTIFICATE-----\n")
	kvKey  = []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")
)

// TestAzureKVDeploysRenewedCertViaOutbox is the S5.12 AN-6 acceptance: a renewed
// certificate is imported into Azure Key Vault through the outbox, and
// redelivery is idempotent.
func TestAzureKVDeploysRenewedCertViaOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	const (
		tok  = "bearer-abc"
		name = "web-prod"
	)
	srv := azurekvtest.New(tok)
	defer srv.Close()

	reg := connector.NewRegistry(func(string) connector.Ops {
		return connector.NewHTTPOps(srv.Client())
	})
	reg.Register(azurekv.New(srv.URL(), azurekv.StaticToken(tok)))

	payload, err := connector.EncodeDeploy("azure-keyvault", connector.NewDeployment(name, kvCert, kvKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "azurekv-1", Payload: payload,
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

	got, ok := srv.Imported(name)
	if !ok || !bytes.Contains(got.PEM, kvCert) || !bytes.Contains(got.PEM, kvKey) {
		t.Fatalf("Key Vault did not receive the renewed credential after outbox delivery")
	}

	if err := reg.Handle(ctx, payload); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	got2, _ := srv.Imported(name)
	if !bytes.Equal(got2.PEM, got.PEM) {
		t.Error("redelivery changed the imported bundle")
	}
}
