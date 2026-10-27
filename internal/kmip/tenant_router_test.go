// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
)

// fakeClientDirectory stands in for the core registry: enrollments by
// username and secret, bindings by certificate fingerprint.
type fakeClientDirectory struct {
	mu          sync.Mutex
	bound       map[string]string // fingerprint -> tenant
	enrollments map[string][2]string
}

func (f *fakeClientDirectory) KMIPClientTenant(_ context.Context, certDER []byte) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tenant, ok := f.bound[crypto.SHA256Hex(certDER)]
	return tenant, ok, nil
}

func (f *fakeClientDirectory) EnrollKMIPClient(_ context.Context, clientID string, enrollmentSecret, certDER []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.enrollments[clientID]
	if !ok || e[1] != string(enrollmentSecret) {
		return "", errors.New("enrollment refused")
	}
	delete(f.enrollments, clientID)
	f.bound[crypto.SHA256Hex(certDER)] = e[0]
	return e[0], nil
}

func (f *fakeClientDirectory) unbind(certDER []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.bound, crypto.SHA256Hex(certDER))
}

// A197: one listener serves every tenant's enrolled clients. A client with
// its own certificate is refused until its request carries the enrollment its
// tenant issued; from then on its certificate alone selects that tenant, and
// it sees only that tenant's objects. A client the deployment's CA issued is
// still served for the configured tenant, a wrong secret enrolls nothing, and
// a client whose binding is removed is refused at its next request.
func TestKMIPListenerServesEachTenantsEnrolledClients(t *testing.T) {
	const serverName = "kmip.tenants.test"
	deployment, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), serverName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ownA, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "appliance-a.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ownB, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "appliance-b.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := &fakeClientDirectory{bound: map[string]string{}, enrollments: map[string][2]string{
		"11111111-1111-4111-8111-111111111111": {"tenant-a", "secret-a"},
		"22222222-2222-4222-8222-222222222222": {"tenant-b", "secret-b"},
	}}
	poolSet := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemKMIP, Workers: 4, Queue: 8})
	t.Cleanup(poolSet.Close)
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	kekBytes, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := seal.NewLocalKEK(kekBytes)
	secret.Wipe(kekBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	runtime, err := NewFactory()(server.KMIPFactoryDeps{
		StartupContext: context.Background(),
		Protocols: config.Protocols{KMIP: config.KMIPProtocol{
			Enabled: true, ClientRegistrations: true, TenantID: "tenant-legacy", Addr: "127.0.0.1:0",
			CertFile: deployment.Signer.CertFile, KeyFile: deployment.Signer.KeyFile, ClientCAFile: deployment.Signer.PeerCAFile,
		}},
		Bulkhead:   poolSet,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		EventLog:   log,
		KeyWrapper: wrapper,
		Clients:    directory,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
		runtime.Close()
	})
	dial := func(material *mtls.SignerPeerMaterial) net.Conn {
		t.Helper()
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := mtls.MutualTLSClientConnFromFiles(ctx, raw, material.ControlPlane.CertFile, material.ControlPlane.KeyFile,
			deployment.ControlPlane.PeerCAFile, serverName)
		if err != nil {
			t.Fatalf("mTLS handshake: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	exchange := func(conn net.Conn, frame []byte) []byte {
		t.Helper()
		if _, err := conn.Write(frame); err != nil {
			t.Fatal(err)
		}
		resp, err := ReadFrame(conn, defaultWireFrameCap)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	enrolling := func(op Operation, payload []byte, username, password string) []byte {
		return kmipRequestFrameWithCredential(op, payload, username, password)
	}
	nameOf := func(conn net.Conn, id string) []string {
		t.Helper()
		root := mustKMIPSuccess(t, exchange(conn, kmipRequestFrame(OperationGetAttributes, kmipGetAttributesPayload(id, attrName))), OperationGetAttributes)
		return allTextValues(root, TagNameValue)
	}

	a := dial(ownA)
	if reason := failureReason(t, exchange(a, kmipRequestFrame(OperationCreate, kmipCreateAES256Payload())), OperationCreate); reason != resultReasonAuthFailed {
		t.Fatalf("an unenrolled client = reason %#x, want Authentication Not Successful", reason)
	}
	if reason := failureReason(t, exchange(a, enrolling(OperationCreate, kmipCreateAES256Payload(), "11111111-1111-4111-8111-111111111111", "wrong")), OperationCreate); reason != resultReasonAuthFailed {
		t.Fatalf("a wrong enrollment secret = reason %#x", reason)
	}
	created := mustKMIPSuccess(t, exchange(a, enrolling(OperationCreate, kmipCreateAES256Payload(), "11111111-1111-4111-8111-111111111111", "secret-a")), OperationCreate)
	aKey := mustFindText(t, created, TagUniqueIdentifier)
	mustKMIPSuccess(t, exchange(a, kmipRequestFrame(OperationAddAttribute, ttlvStructure(TagRequestPayload, ttlvText(TagUniqueIdentifier, aKey),
		kmipAttribute(attrName, kmipNameValue("tenant-a-key"))))), OperationAddAttribute)
	// A new connection with the same certificate needs no credential.
	if ids := locateIDs(t, exchange(dial(ownA), kmipRequestFrame(OperationLocate, nil))); len(ids) != 1 || ids[0] != aKey {
		t.Fatalf("tenant A's enrolled client locates %v", ids)
	}

	b := dial(ownB)
	mustKMIPSuccess(t, exchange(b, enrolling(OperationQuery, ttlvStructure(TagRequestPayload, ttlvEnumeration(TagQueryFunction, queryFunctionOperations)),
		"22222222-2222-4222-8222-222222222222", "secret-b")), OperationQuery)
	if ids := locateIDs(t, exchange(b, kmipRequestFrame(OperationLocate, nil))); len(ids) != 0 {
		t.Fatalf("tenant B sees tenant A's objects: %v", ids)
	}
	if reason := failureReason(t, exchange(b, kmipRequestFrame(OperationGet, kmipUniqueIDPayload(aKey))), OperationGet); reason != resultReasonItemNotFound {
		t.Fatalf("tenant B's Get of tenant A's key = reason %#x, want Item Not Found", reason)
	}
	bKey := mustFindText(t, mustKMIPSuccess(t, exchange(b, kmipRequestFrame(OperationCreate, kmipCreateAES256Payload())), OperationCreate), TagUniqueIdentifier)
	if names := nameOf(b, bKey); len(names) != 0 {
		t.Fatalf("tenant B's own key carries tenant A's names %v", names)
	}
	if names := nameOf(a, aKey); len(names) != 1 || names[0] != "tenant-a-key" {
		t.Fatalf("tenant A's key names = %v", names)
	}

	issued := dial(deployment)
	if ids := locateIDs(t, exchange(issued, kmipRequestFrame(OperationLocate, nil))); len(ids) != 0 {
		t.Fatalf("the configured tenant's CA-issued client sees %v", ids)
	}

	certB, err := readCertificateDER(ownB.ControlPlane.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	directory.unbind(certB)
	if reason := failureReason(t, exchange(b, kmipRequestFrame(OperationLocate, nil)), OperationLocate); reason != resultReasonAuthFailed {
		t.Fatalf("a client whose binding was removed = reason %#x", reason)
	}
}

func kmipRequestFrameWithCredential(op Operation, payload []byte, username, password string) []byte {
	batchChildren := [][]byte{ttlvEnumeration(TagOperation, int32(op))}
	if len(payload) > 0 {
		batchChildren = append(batchChildren, payload)
	}
	return ttlvStructure(TagRequestMessage,
		ttlvStructure(TagRequestHeader,
			ttlvStructure(TagProtocolVersion, ttlvInteger(TagProtocolVersionMajor, 1), ttlvInteger(TagProtocolVersionMinor, 4)),
			ttlvStructure(TagAuthentication, ttlvStructure(TagCredential,
				ttlvEnumeration(TagCredentialType, credentialTypeUsernameAndPassword),
				ttlvStructure(TagCredentialValue, ttlvText(TagUsername, username), ttlvText(TagPassword, password)),
			)),
			ttlvInteger(TagBatchCount, 1),
		),
		ttlvStructure(TagBatchItem, batchChildren...),
	)
}

func readCertificateDER(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- test-generated TLS material in the test's temp dir (CWE-22)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM certificate")
	}
	return block.Bytes, nil
}
