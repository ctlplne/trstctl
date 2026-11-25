// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/server"
)

func TestKMIPHeldConnectionEndsAtAbsoluteLifetime(t *testing.T) {
	const serverName = "kmip.connection-age.test"
	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), serverName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	log, wrapper := kmipReplicaFixture(t)
	pools := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemKMIP, Workers: 1, Queue: 2})
	t.Cleanup(pools.Close)
	h := startKMIPWireRuntime(t, server.KMIPFactoryDeps{
		StartupContext: context.Background(),
		Protocols: config.Protocols{KMIP: config.KMIPProtocol{
			Enabled: true, TenantID: "kmip-connection-age", Addr: "127.0.0.1:0",
			CertFile: material.Signer.CertFile, KeyFile: material.Signer.KeyFile,
			ClientCAFile: material.Signer.PeerCAFile,
		}},
		ProtocolTenant: "kmip-connection-age",
		Bulkhead:       pools,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		EventLog:       log,
		KeyWrapper:     wrapper,
	}, material, serverName)
	// Set the test's connection cap before the listener accepts any client.
	h.runtime.(*Runtime).connectionLifetime.Store(int64(3 * time.Second))
	conn := h.dial(t)
	defer func() { _ = conn.Close() }()
	query := kmipRequestFrame(OperationQuery, ttlvStructure(TagRequestPayload,
		ttlvEnumeration(TagQueryFunction, queryFunctionOperations)))
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(conn, defaultWireFrameCap); err != nil {
		t.Fatalf("initial Query failed: %v", err)
	}
	time.Sleep(3200 * time.Millisecond)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = conn.Write(query)
	if _, err := ReadFrame(conn, defaultWireFrameCap); err == nil {
		t.Fatal("KMIP kept serving after the connection's absolute lifetime")
	}
}
