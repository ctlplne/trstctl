package projections_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"certctl.io/certctl/internal/connector"
	"certctl.io/certctl/internal/connector/example"
	"certctl.io/certctl/internal/orchestrator"
)

var (
	deployCert = []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n")
	deployKey  = []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")
)

// TestConnectorDeploysViaOutbox is the AN-6 acceptance for the connector SDK: a
// deploy intent enqueued on the outbox is delivered to the connector, which
// installs the credential, and redelivery is idempotent.
func TestConnectorDeploysViaOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	ops := connector.NewMemoryOps()
	reg := connector.NewRegistry(func(string) connector.Ops { return ops })
	reg.Register(example.New("/srv/tls", "reload"))

	payload, err := connector.EncodeDeploy("filereload", connector.NewDeployment("node-1", deployCert, deployKey))
	if err != nil {
		t.Fatal(err)
	}

	// Enqueue the deploy intent in a tenant transaction (AN-6: same tx as the
	// state change in production).
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "deploy-1", Payload: payload,
		})
		return e
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// The outbox dispatches the intent to the connector registry.
	handler := orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		return reg.Handle(ctx, m.Payload)
	})
	if n, err := ob.Dispatch(ctx, handler); err != nil || n != 1 {
		t.Fatalf("Dispatch n=%d err=%v, want 1", n, err)
	}

	got, ok := ops.File("/srv/tls/tls.crt")
	if !ok || string(got) != string(deployCert) {
		t.Fatalf("connector did not install the certificate via the outbox (ok=%v)", ok)
	}

	// At-least-once redelivery is idempotent: handling the same payload again
	// leaves exactly one target in the same state.
	if err := reg.Handle(ctx, payload); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	if n := len(ops.Files()); n != 2 { // tls.crt + tls.key, not duplicated
		t.Errorf("after redelivery the target has %d files, want 2 (idempotent)", n)
	}
}
