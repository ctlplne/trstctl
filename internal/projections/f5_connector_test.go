package projections_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
	"trstctl.com/trstctl/internal/orchestrator"
)

var (
	f5Cert = []byte("-----BEGIN CERTIFICATE-----\nrenewed-leaf\n-----END CERTIFICATE-----\n")
	f5Key  = []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")
)

// TestF5DeploysRenewedCertViaOutbox is the S5.10 AN-6 acceptance: a renewed
// certificate is deployed to a BIG-IP through the outbox over iControl REST, and
// redelivery is idempotent.
func TestF5DeploysRenewedCertViaOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	const profile = "clientssl_app"
	srv := f5test.New("admin", "s3cret")
	defer srv.Close()

	reg := connector.NewRegistry(func(string) connector.Ops {
		return connector.NewHTTPOps(srv.Client())
	})
	reg.Register(f5.New(srv.URL(), profile, f5.WithBasicAuth("admin", "s3cret")))

	payload, err := connector.EncodeDeploy("f5", connector.NewDeployment("bigip-1", f5Cert, f5Key))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "f5-1", Payload: payload,
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

	gotCert, ok := srv.Uploaded(profile + ".crt")
	if !ok || !bytes.Equal(gotCert, f5Cert) {
		t.Fatalf("BIG-IP did not receive the renewed certificate after outbox delivery")
	}
	chain, ok := srv.Profile(profile)
	if !ok || chain.Cert != profile+".crt" || chain.Key != profile+".key" {
		t.Fatalf("Client SSL profile not bound to the renewed credential: %+v ok=%v", chain, ok)
	}

	callsAfterFirst := srv.Calls()
	if err := reg.Handle(ctx, payload); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	chain2, _ := srv.Profile(profile)
	if chain2 != chain {
		t.Error("redelivery changed the bound chain")
	}
	if srv.Calls() <= callsAfterFirst {
		t.Error("redelivery should have re-issued the (idempotent) install calls")
	}
}
