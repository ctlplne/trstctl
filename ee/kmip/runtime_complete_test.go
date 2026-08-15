// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
)

// TestKMIPOASIS14QueryOverMTLSListener proves the complete OASIS-profile path is
// reachable through NewFactory's shipped TLS listener, then starts a new runtime
// over the same event log and KEK to prove lifecycle replay. It never constructs
// Server or its operation registry directly.
func TestKMIPOASIS14QueryOverMTLSListener(t *testing.T) {
	const serverName = "kmip.trstctl.test"
	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), serverName, time.Hour)
	if err != nil {
		t.Fatalf("generate KMIP mTLS material: %v", err)
	}
	// The runtime refuses to run without its own lane (A2/V11): the old
	// protocols-pool fallback was the silent share that starved every other
	// protocol, so this fixture supplies the kmip lane the contract demands.
	poolSet := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemKMIP, Workers: 1, Queue: 2})
	t.Cleanup(poolSet.Close)
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("open KMIP event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	kekBytes, err := seal.GenerateKEK()
	if err != nil {
		t.Fatalf("generate KMIP KEK: %v", err)
	}
	wrapper, err := seal.NewLocalKEK(kekBytes)
	secret.Wipe(kekBytes)
	if err != nil {
		t.Fatalf("construct KMIP KEK: %v", err)
	}
	t.Cleanup(wrapper.Destroy)
	deps := server.KMIPFactoryDeps{
		Protocols: config.Protocols{KMIP: config.KMIPProtocol{
			Enabled: true, TenantID: "tenant-listener", Addr: "127.0.0.1:5696",
			CertFile: material.Signer.CertFile, KeyFile: material.Signer.KeyFile,
			ClientCAFile: material.Signer.PeerCAFile,
		}},
		ProtocolTenant: "tenant-listener",
		Bulkhead:       poolSet,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		EventLog:       log,
		KeyWrapper:     wrapper,
	}
	first := startKMIPWireRuntime(t, deps, material, serverName)
	conn := first.dial(t)
	query := ttlvStructure(TagRequestPayload,
		ttlvEnumeration(TagQueryFunction, queryFunctionOperations),
		ttlvEnumeration(TagQueryFunction, queryFunctionProfiles),
	)
	response := kmipWireRequest(t, conn, OperationQuery, query)
	root := mustKMIPSuccess(t, response, OperationQuery)
	profiles := allEnumerationValues(root, TagProfileName)
	if !containsEnumeration(profiles, profileSymmetricKeyLifecycleServer14) {
		t.Fatalf("mTLS Query profiles = %v, want Symmetric Key Lifecycle Server 1.4", profiles)
	}
	if operations := allEnumerationValues(root, TagOperation); !containsEnumeration(operations, int32(OperationRegister)) || !containsEnumeration(operations, int32(OperationDiscoverVersions)) {
		t.Fatalf("mTLS Query operations = %v, want Register + DiscoverVersions", operations)
	}
	discover := ttlvStructure(TagRequestPayload, protocolVersionTTLV(1, 4), protocolVersionTTLV(1, 3))
	discoverRoot := mustKMIPSuccess(t, kmipWireRequest(t, conn, OperationDiscoverVersions, discover), OperationDiscoverVersions)
	versions := protocolVersionsIn(mustFindNode(t, discoverRoot, TagResponsePayload))
	if len(versions) != 1 || versions[0] != (protocolVersion{major: 1, minor: 4}) {
		t.Fatalf("mTLS DiscoverVersions = %+v, want negotiated 1.4", versions)
	}

	wrappingRoot := mustKMIPSuccess(t, kmipWireRequest(t, conn, OperationCreate, kmipCreateAES256Payload()), OperationCreate)
	wrappingID := mustFindText(t, wrappingRoot, TagUniqueIdentifier)
	keyMaterial := []byte("0123456789abcdef0123456789abcdef")
	defer secret.Wipe(keyMaterial)
	registeredRoot := mustKMIPSuccess(t, kmipWireRequest(t, conn, OperationRegister, kmipRegisterRawAES256Payload(keyMaterial)), OperationRegister)
	registeredID := mustFindText(t, registeredRoot, TagUniqueIdentifier)
	wrappedRoot := mustKMIPSuccess(t, kmipWireRequest(t, conn, OperationGet, kmipGetWrappedPayload(registeredID, wrappingID, encodingOptionNoEncoding)), OperationGet)
	wrappedObject := mustFindNode(t, wrappedRoot, TagSymmetricKey)
	if _, ok := findNode(wrappedObject, TagKeyWrappingData); !ok {
		t.Fatal("mTLS wrapped Get omitted KeyWrappingData")
	}
	clonePayload := ttlvStructure(TagRequestPayload,
		ttlvEnumeration(TagObjectType, objectTypeSymmetricKey),
		ttlvStructure(TagTemplateAttribute),
		encodeParsedTTLV(wrappedObject),
	)
	cloneRoot := mustKMIPSuccess(t, kmipWireRequest(t, conn, OperationRegister, clonePayload), OperationRegister)
	cloneID := mustFindText(t, cloneRoot, TagUniqueIdentifier)
	cloneGet := mustKMIPSuccess(t, kmipWireRequest(t, conn, OperationGet, kmipUniqueIDPayload(cloneID)), OperationGet)
	if got := mustFindNode(t, cloneGet, TagKeyMaterial).Value; !bytes.Equal(got, keyMaterial) {
		t.Fatalf("mTLS wrapped Register clone = %x, want %x", got, keyMaterial)
	}
	mustKMIPSuccess(t, kmipWireRequest(t, conn, OperationRevoke, kmipUniqueIDPayload(registeredID)), OperationRevoke)
	mustKMIPSuccess(t, kmipWireRequest(t, conn, OperationDestroy, kmipUniqueIDPayload(cloneID)), OperationDestroy)
	_ = conn.Close()
	first.stop(t)

	// A newly constructed shipped runtime replays sealed state and preserves both
	// lifecycle terminal states. A process-local registry would return success here.
	second := startKMIPWireRuntime(t, deps, material, serverName)
	conn = second.dial(t)
	if status := responseStatus(t, kmipWireRequest(t, conn, OperationGet, kmipUniqueIDPayload(registeredID)), OperationGet); status != resultStatusOperationFailed {
		t.Fatalf("Get replayed revoked object status=%d, want failure", status)
	}
	if status := responseStatus(t, kmipWireRequest(t, conn, OperationGet, kmipUniqueIDPayload(cloneID)), OperationGet); status != resultStatusOperationFailed {
		t.Fatalf("Get replayed destroyed object status=%d, want failure", status)
	}
	_ = conn.Close()
	second.stop(t)
}

type kmipWireRuntime struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan error
	runtime server.KMIPRuntime
	addr    string
	stopOne sync.Once
	stopErr error
	client  *mtls.SignerPeerMaterial
	name    string
}

func startKMIPWireRuntime(t *testing.T, deps server.KMIPFactoryDeps, material *mtls.SignerPeerMaterial, serverName string) *kmipWireRuntime {
	t.Helper()
	runtime, err := NewFactory()(deps)
	if err != nil {
		t.Fatalf("build shipped KMIP runtime: %v", err)
	}
	socketPath := filepath.Join("/tmp", fmt.Sprintf("trstctl-kmip-%d.sock", time.Now().UnixNano()))
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		runtime.Close()
		t.Fatalf("listen KMIP socket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &kmipWireRuntime{
		ctx: ctx, cancel: cancel, done: make(chan error, 1), runtime: runtime,
		addr: ln.Addr().String(), client: material, name: serverName,
	}
	go func() { h.done <- runtime.Serve(ctx, ln) }()
	t.Cleanup(func() {
		h.stop(t)
		_ = os.Remove(socketPath)
	})
	return h
}

func (h *kmipWireRuntime) dial(t *testing.T) net.Conn {
	t.Helper()
	raw, err := net.DialTimeout("unix", h.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial KMIP listener: %v", err)
	}
	conn, err := mtls.MutualTLSClientConnFromFiles(h.ctx, raw,
		h.client.ControlPlane.CertFile, h.client.ControlPlane.KeyFile,
		h.client.ControlPlane.PeerCAFile, h.name,
	)
	if err != nil {
		t.Fatalf("KMIP mTLS handshake: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = conn.Close()
		t.Fatalf("set KMIP client deadline: %v", err)
	}
	return conn
}

func (h *kmipWireRuntime) stop(t *testing.T) {
	t.Helper()
	h.stopOne.Do(func() {
		h.cancel()
		select {
		case h.stopErr = <-h.done:
		case <-time.After(5 * time.Second):
			h.stopErr = fmt.Errorf("KMIP listener did not stop")
		}
		h.runtime.Close()
	})
	if h.stopErr != nil {
		t.Errorf("KMIP listener shutdown: %v", h.stopErr)
	}
}

func kmipWireRequest(t *testing.T, conn net.Conn, operation Operation, payload []byte) []byte {
	t.Helper()
	if _, err := conn.Write(kmipRequestFrame(operation, payload)); err != nil {
		t.Fatalf("write %s frame: %v", operationName(operation), err)
	}
	response, err := ReadFrame(conn, defaultWireFrameCap)
	if err != nil {
		t.Fatalf("read %s response: %v", operationName(operation), err)
	}
	return response
}
