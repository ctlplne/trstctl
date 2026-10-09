// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
)

func TestKMIPFactoryFailsClosedWithoutDurabilityAndRestoresWithIt(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	pools := bulkhead.Default()
	t.Cleanup(pools.Close)
	deps := server.KMIPFactoryDeps{
		StartupContext: context.Background(),
		Protocols: config.Protocols{KMIP: config.KMIPProtocol{
			Enabled: true, TenantID: tenantID, Addr: "127.0.0.1:5696",
			CertFile: "server.crt", KeyFile: "server.key", ClientCAFile: "clients.pem",
		}},
		ProtocolTenant: tenantID,
		Bulkhead:       pools,
	}
	factory := NewFactory()
	if _, err := factory(deps); err == nil || !strings.Contains(err.Error(), "event log") {
		t.Fatalf("factory without event log error = %v", err)
	}

	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	deps.EventLog = log
	if _, err := factory(deps); err == nil || !strings.Contains(err.Error(), "key wrapper") {
		t.Fatalf("factory without key wrapper error = %v", err)
	}

	kekBytes, err := seal.GenerateKEK()
	if err != nil {
		t.Fatalf("generate KEK: %v", err)
	}
	wrapper, err := seal.NewLocalKEK(kekBytes)
	secret.Wipe(kekBytes)
	if err != nil {
		t.Fatalf("construct KEK: %v", err)
	}
	t.Cleanup(wrapper.Destroy)
	deps.KeyWrapper = wrapper
	runtime, err := factory(deps)
	if err != nil {
		t.Fatalf("factory with durability dependencies: %v", err)
	}
	if runtime == nil {
		t.Fatal("factory returned nil runtime")
	}
	runtime.Close()
	canceled, stop := context.WithCancel(context.Background())
	stop()
	deps.StartupContext = canceled
	if _, err := factory(deps); !errors.Is(err, context.Canceled) {
		t.Fatalf("KMIP replay ignored canceled startup context: %v", err)
	}
}
