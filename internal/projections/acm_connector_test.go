package projections_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestACMDeploysRenewedCertViaOutbox is the S5.11 AN-6 acceptance: a renewed
// certificate is imported into AWS ACM through the outbox over a SigV4-signed
// ImportCertificate call, and redelivery is idempotent.
func TestACMDeploysRenewedCertViaOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	const (
		ak  = "AKIDEXAMPLE"
		sk  = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		arn = "arn:aws:acm:us-east-1:123456789012:certificate/abcd"
	)
	acmCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("renewed-leaf")})
	acmKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("renewed-key")})

	srv := acmtest.New(ak, sk)
	defer srv.Close()

	reg := connector.NewRegistry(func(string) connector.Ops {
		return connector.NewHTTPOps(srv.Client())
	})
	reg.Register(acm.New("us-east-1", acm.Credentials{AccessKeyID: ak, SecretAccessKey: []byte(sk)}, acm.WithEndpoint(srv.URL())))

	payload, err := connector.EncodeDeploy("aws-acm", connector.NewDeployment(arn, acmCert, acmKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "acm-1", Payload: payload,
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

	got, ok := srv.Imported(arn)
	if !ok || !bytes.Equal(got.Certificate, acmCert) || !bytes.Equal(got.PrivateKey, acmKey) {
		t.Fatalf("ACM did not receive the renewed credential after outbox delivery")
	}

	if err := reg.Handle(ctx, payload); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	got2, _ := srv.Imported(arn)
	if !bytes.Equal(got2.Certificate, got.Certificate) || !bytes.Equal(got2.PrivateKey, got.PrivateKey) {
		t.Error("redelivery changed the imported credential")
	}
}
