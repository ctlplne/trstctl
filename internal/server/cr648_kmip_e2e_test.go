// SPDX-License-Identifier: BUSL-1.1

package server_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	"trstctl.com/trstctl/internal/kmip"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/tenantseal"
)

type cr648TestAccess struct{ wrapper seal.KeyWrapper }

func (a cr648TestAccess) WithTenant(_ context.Context, _ string, fn func(tenantseal.Cipher) error) error {
	return fn(cr648TestCipher(a))
}

type cr648TestCipher struct{ wrapper seal.KeyWrapper }

func (c cr648TestCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	return seal.Seal(c.wrapper, plaintext, aad)
}

func (c cr648TestCipher) Open(container, aad []byte) ([]byte, error) {
	return seal.Open(c.wrapper, container, aad)
}

func (c cr648TestCipher) VerifyRewrapPair(before, after, aad []byte) (bool, error) {
	first, err := c.Open(before, aad)
	if err != nil {
		return false, err
	}
	defer secret.Wipe(first)
	second, err := c.Open(after, aad)
	if err != nil {
		return false, err
	}
	defer secret.Wipe(second)
	return bytes.Equal(first, second), nil
}

type cr648Logs struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *cr648Logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *cr648Logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func cr648WritePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func cr648Find(n kmip.TTLV, tag uint32) (kmip.TTLV, bool) {
	if n.Tag == tag {
		return n, true
	}
	for _, c := range n.Children {
		if f, ok := cr648Find(c, tag); ok {
			return f, true
		}
	}
	return kmip.TTLV{}, false
}

// CR-648 end to end. The KMIP listener runs in client-CA mode with
// protocols.kmip.client_ca_file set to the deployment's own issuing CA (the
// documented setup: docs/features/secrets.md:1537 and :1580-1582, "the clients
// the deployment's CA issued for that tenant"). The client certificate is
// issued through the product (served EST) and revoked through the product's
// API (POST /api/v1/certificates/bulk-revoke); the served OCSP responder then
// answers revoked. A KMIP operation is then sent on the connection opened
// before the revoke and on a new connection.
func TestCR648KMIPClientCAModeServesACertificateRevokedThroughTheProduct(t *testing.T) {
	product := server.NewCR648Product(t)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "client-ca.pem")
	cr648WritePEM(t, caFile, "CERTIFICATE", product.CACertDER)
	const serverName = "kmip.cr648.test"
	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), serverName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	poolSet := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemKMIP, Workers: 2, Queue: 2})
	t.Cleanup(poolSet.Close)
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
	evlog, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true},
		events.WithRequiredAppendAdmission(), events.WithAppendAdmission(func(ctx context.Context, event events.Event,
			publish func(context.Context) (events.Event, error),
		) (events.Event, error) {
			if err := server.ValidateSealedIngressCandidate(ctx, cr648TestAccess{wrapper: wrapper}, event); err != nil {
				return events.Event{}, err
			}
			return publish(ctx)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = evlog.Close() })
	logs := &cr648Logs{}
	runtime, err := kmip.NewFactory()(server.KMIPFactoryDeps{
		StartupContext: context.Background(),
		Protocols: config.Protocols{KMIP: config.KMIPProtocol{
			Enabled: true, TenantID: product.Tenant, Addr: "127.0.0.1:5696",
			CertFile: material.Signer.CertFile, KeyFile: material.Signer.KeyFile,
			ClientCAFile: caFile,
		}},
		ProtocolTenant:            product.Tenant,
		Bulkhead:                  poolSet,
		Log:                       slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		EventLog:                  evlog,
		KeyWrapper:                wrapper,
		ClientCertificateStanding: product.ClientCertificateStanding(),
	})
	if err != nil {
		t.Fatalf("build shipped KMIP runtime: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Serve(ctx, ln) }()
	var conns []net.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
		cancel()
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(35 * time.Second):
			t.Log("KMIP Serve did not return within 35 s")
		}
		runtime.Close()
	})

	const cn = "kmip-client.cr648.test"
	leafDER, keyPKCS8 := product.IssueClientCertificate(cn)
	certFile, keyFile := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	cr648WritePEM(t, certFile, "CERTIFICATE", leafDER)
	cr648WritePEM(t, keyFile, "PRIVATE KEY", keyPKCS8)
	secret.Wipe(keyPKCS8)

	dial := func() (net.Conn, error) {
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			return nil, err
		}
		conn, err := mtls.MutualTLSClientConnFromFiles(ctx, raw, certFile, keyFile, material.ControlPlane.PeerCAFile, serverName)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		conns = append(conns, conn)
		return conn, nil
	}
	exchange := func(conn net.Conn, op kmip.Operation, payload []byte) (kmip.ClientResponseItem, error) {
		frame, err := kmip.EncodeClientRequest(1, 4, kmip.ClientRequestItem{Operation: op, Payload: payload})
		if err != nil {
			return kmip.ClientResponseItem{}, err
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(frame); err != nil {
			return kmip.ClientResponseItem{}, err
		}
		resp, err := kmip.ReadFrame(conn, 1<<20)
		if err != nil {
			return kmip.ClientResponseItem{}, err
		}
		items, err := kmip.DecodeClientResponse(resp)
		if err != nil {
			return kmip.ClientResponseItem{}, err
		}
		if len(items) != 1 {
			return kmip.ClientResponseItem{}, fmt.Errorf("%d batch items", len(items))
		}
		return items[0], nil
	}
	queryPayload := kmip.EncodeStructure(kmip.TagRequestPayload, kmip.EncodeEnumeration(kmip.TagQueryFunction, 1))
	createPayload := kmip.EncodeStructure(kmip.TagRequestPayload,
		kmip.EncodeEnumeration(kmip.TagObjectType, 2), // KMIP SymmetricKey
		kmip.EncodeStructure(kmip.TagTemplateAttribute,
			kmip.EncodeStructure(kmip.TagAttribute,
				kmip.EncodeText(kmip.TagAttributeName, "Cryptographic Algorithm"),
				kmip.EncodeEnumeration(kmip.TagAttributeValue, 3)), // KMIP AES
			kmip.EncodeStructure(kmip.TagAttribute,
				kmip.EncodeText(kmip.TagAttributeName, "Cryptographic Length"),
				kmip.EncodeInteger(kmip.TagAttributeValue, 256))))
	create := func(conn net.Conn) (string, bool) {
		t.Helper()
		item, err := exchange(conn, kmip.OperationCreate, createPayload)
		if err != nil || item.ResultStatus != kmip.ResultStatusSuccess {
			t.Logf("KMIP Create: status=%d message=%q err=%v", item.ResultStatus, item.ResultMessage, err)
			return "", false
		}
		uid, ok := cr648Find(item.Payload, kmip.TagUniqueIdentifier)
		return string(uid.Value), ok
	}
	getKeyLen := func(conn net.Conn, id string) int {
		t.Helper()
		item, err := exchange(conn, kmip.OperationGet, kmip.EncodeStructure(kmip.TagRequestPayload, kmip.EncodeText(kmip.TagUniqueIdentifier, id)))
		if err != nil || item.ResultStatus != kmip.ResultStatusSuccess {
			t.Logf("KMIP Get: status=%d message=%q err=%v", item.ResultStatus, item.ResultMessage, err)
			return 0
		}
		material, ok := cr648Find(item.Payload, kmip.TagKeyMaterial)
		if !ok {
			return 0
		}
		length := len(material.Value)
		secret.Wipe(material.Value)
		return length
	}
	served := func(label string, conn net.Conn) bool {
		item, err := exchange(conn, kmip.OperationQuery, queryPayload)
		if err != nil {
			t.Logf("%s: Query not served: %v", label, err)
			return false
		}
		t.Logf("%s: Query result status %d (success = %d) %s", label, item.ResultStatus, kmip.ResultStatusSuccess, item.ResultMessage)
		return item.ResultStatus == kmip.ResultStatusSuccess
	}

	held, err := dial()
	if err != nil {
		t.Fatalf("control: KMIP handshake with the product-issued certificate before revocation: %v", err)
	}
	if !served("control, before revocation", held) {
		t.Fatal("control: the product-issued client certificate is not served before revocation")
	}
	keyID, created := create(held)
	if !created || getKeyLen(held, keyID) != 32 {
		t.Fatal("control: the valid product-issued client did not Create and Get an AES-256 key")
	}
	reason, ocspStatus := product.RevokeThroughAPI(cn, leafDER)
	if ocspStatus != crypto.OCSPRevoked {
		t.Fatalf("precondition: served OCSP status after the API revoke = %q, want revoked", ocspStatus)
	}
	t.Logf("revoked through POST /api/v1/certificates/bulk-revoke (reason %s); the product's served OCSP responder answers %q", reason, ocspStatus)

	heldServed := served("already-open connection, after revocation", held)
	heldKeyLen := getKeyLen(held, keyID)
	freshServed, freshCreated, freshKeyLen := false, false, 0
	fresh, err := dial()
	if err != nil {
		t.Logf("new connection, after revocation: handshake refused: %v", err)
	} else {
		freshServed = served("new connection, after revocation", fresh)
		_, freshCreated = create(fresh)
		freshKeyLen = getKeyLen(fresh, keyID)
		t.Logf("new connection, after revocation: Create=%v, Get returned %d bytes of key material", freshCreated, freshKeyLen)
	}
	if heldServed || heldKeyLen > 0 || freshServed || freshCreated || freshKeyLen > 0 {
		t.Errorf("CR-648: product-issued client certificate revoked through the API (served OCSP %q), yet KMIP served it: held Query=%v, held Get=%d bytes, fresh Query=%v, fresh Create=%v, fresh Get=%d bytes; KMIP runtime log (%d bytes): %q",
			ocspStatus, heldServed, heldKeyLen, freshServed, freshCreated, freshKeyLen, len(logs.String()), logs.String())
	}
	if !strings.Contains(logs.String(), "KMIP client certificate refused") {
		t.Fatal("revoked KMIP client certificate refusal was not logged")
	}
	var audited bool
	if err := evlog.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == product.Tenant && event.Type == "kmip.client_certificate_refused" {
			audited = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !audited {
		t.Fatal("revoked KMIP client certificate refusal was not audited")
	}
}
