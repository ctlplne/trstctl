package projections_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/iis"
	"trstctl.com/trstctl/internal/connector/iis/iistest"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
)

var (
	iisCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBiDCCAS2gAwIBAgIBATAKBggqhkjOPQQDAjAlMSMwIQYDVQQDExpjb25mb3Jt
YW5jZS5jb25uZWN0b3IudGVzdDAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAw
MDBaMCUxIzAhBgNVBAMTGmNvbmZvcm1hbmNlLmNvbm5lY3Rvci50ZXN0MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE4TYNtNbbVlPcVpyznJuujANXTbsaRNL5D41K
VfB5GdJEG372Pgtn59Mp7+1+PUbyHTbaKJ1RU0n6vgW5/BCC1aNOMEwwDgYDVR0P
AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMCUGA1UdEQQeMByCGmNvbmZv
cm1hbmNlLmNvbm5lY3Rvci50ZXN0MAoGCCqGSM49BAMCA0kAMEYCIQD2NqiRyoq8
T1vJogCsCMRDiEMMsA04Qhbs5uF149egpgIhALTX3I6Xe4dQk3GMTEaXC5GWXkaj
O9xXOtFRqPTY0dXn
-----END CERTIFICATE-----
`)
	iisKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2drNvkGQeqFUx3xE
zejpKQlXChZFd7J3qw/JXoL+x72hRANCAAThNg201ttWU9xWnLOcm66MA1dNuxpE
0vkPjUpV8HkZ0kQbfvY+C2fn0ynv7X49RvIdNtoonVFTSfq+Bbn8EILV
-----END PRIVATE KEY-----
`)
)

// TestIISDeploysRenewedCertViaOutbox is the S5.8 AN-6 acceptance: a renewed
// certificate is deployed to IIS through the outbox, and redelivery is
// idempotent.
func TestIISDeploysRenewedCertViaOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	const binding = "0.0.0.0:443"
	srv := iistest.New()
	reg := connector.NewRegistry(func(string) connector.Ops { return srv })
	reg.Register(iis.New(binding))

	payload, err := connector.EncodeDeploy("iis", connector.NewDeployment("default-site", iisCert, iisKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "iis-1", Payload: payload,
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

	thumb, _ := certinfo.Thumbprint(iisCert)
	if got, ok := srv.Binding(binding); !ok || got != thumb {
		t.Fatalf("IIS binding = %q (ok=%v), want the cert thumbprint %q", got, ok, thumb)
	}

	if err := reg.Handle(ctx, payload); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	if got, _ := srv.Binding(binding); got != thumb {
		t.Error("redelivery changed the bound certificate")
	}
}
