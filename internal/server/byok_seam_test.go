package server

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestKMIPRequiresEditionFactory(t *testing.T) {
	ctx := context.Background()
	srv, err := Build(ctx, Deps{
		Store: newServerTestStore(t),
		Log:   openServerFederationSeamTestLog(t),
		Protocols: config.Protocols{KMIP: config.KMIPProtocol{
			Enabled:      true,
			TenantID:     servedTestTenant,
			CertFile:     "kmip-server.crt",
			KeyFile:      "kmip-server.key",
			ClientCAFile: "kmip-clients.crt",
		}},
	})
	if err != nil {
		t.Fatalf("build server with unlicensed KMIP config: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	if srv.KMIPServed() {
		t.Fatal("KMIP must not mount without the licensed edition factory")
	}
}
