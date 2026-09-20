// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/netscaler"
	"trstctl.com/trstctl/internal/connector/netscaler/netscalertest"
	"trstctl.com/trstctl/internal/orchestrator"
)

var (
	nsCert = []byte("-----BEGIN CERTIFICATE-----\nrenewed-leaf\n-----END CERTIFICATE-----\n")
	nsKey  = []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")
)

// TestNetScalerDeploysRenewedCertViaOutbox is the S5.13.1 AN-6 acceptance: a
// renewed certificate is uploaded and rebound on a Citrix ADC (NetScaler)
// through the outbox over NITRO, and redelivery is idempotent.
func TestNetScalerDeploysRenewedCertViaOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	const (
		user    = "nsroot"
		pass    = "s3cret"
		certkey = "web-prod"
	)
	srv := netscalertest.New(user, pass)
	defer srv.Close()

	reg := connector.NewRegistry(func(string) connector.Ops {
		return connector.NewHTTPOps(srv.Client())
	})
	reg.Register(netscaler.New(srv.URL(), user, []byte(pass)))

	payload, err := connector.EncodeDeploy("netscaler", connector.NewDeployment(certkey, nsCert, nsKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "netscaler-1", Payload: payload,
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

	// D4: uploaded FILE names carry the fingerprint so a later deploy leaves the
	// predecessor for a rollback. The certkey object — what vservers bind to —
	// keeps its name.
	base := connector.DeployedObjectName(certkey, connector.CertificateFingerprint(nsCert))
	gotCert, ok := srv.File(base + ".crt")
	if !ok || !bytes.Equal(gotCert, nsCert) {
		t.Fatalf("NetScaler did not receive the renewed certificate after outbox delivery")
	}
	b, ok := srv.Binding(certkey)
	if !ok || b.Cert != base+".crt" || b.Key != base+".key" {
		t.Fatalf("SSL certkey not rebound to the renewed files: %+v ok=%v", b, ok)
	}

	if err := reg.Handle(ctx, payload); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	b2, _ := srv.Binding(certkey)
	if b2 != b {
		t.Error("redelivery changed the certkey binding")
	}
}
