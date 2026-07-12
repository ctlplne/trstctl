// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestKMIPOASIS14QueryOverMTLSListener proves that the OASIS-profile operation
// is reachable through the shipped listener boundary, not just by constructing
// Server and calling its dispatcher directly.
func TestKMIPOASIS14QueryOverMTLSListener(t *testing.T) {
	const serverName = "kmip.trstctl.test"
	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), serverName, time.Hour)
	if err != nil {
		t.Fatalf("generate KMIP mTLS material: %v", err)
	}
	socketPath := filepath.Join("/tmp", fmt.Sprintf("trstctl-kmip-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	pool := bulkhead.New(bulkhead.Config{Name: "kmip-test", Workers: 1, Queue: 2})
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &Runtime{
		certFile:     material.Signer.CertFile,
		keyFile:      material.Signer.KeyFile,
		clientCAFile: material.Signer.PeerCAFile,
		service:      New("tenant-listener", VerifiedClientCertAuthenticator{}, &auditsink.Recorder{}),
		pool:         pool,
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("KMIP listener shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("KMIP listener did not stop")
		}
		pool.Close()
		runtime.Close()
	})

	credentials, err := mtls.SignerClientCredentials(material.ControlPlane, serverName)
	if err != nil {
		t.Fatalf("build KMIP client credentials: %v", err)
	}
	raw, err := net.DialTimeout("unix", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial KMIP listener: %v", err)
	}
	conn, _, err := credentials.ClientHandshake(ctx, serverName, raw)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("KMIP mTLS handshake: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set KMIP client deadline: %v", err)
	}
	query := ttlvStructure(TagRequestPayload,
		ttlvEnumeration(TagQueryFunction, queryFunctionProfiles),
	)
	if _, err := conn.Write(kmipRequestFrame(OperationQuery, query)); err != nil {
		t.Fatalf("write Query frame: %v", err)
	}
	response, err := ReadFrame(conn, defaultWireFrameCap)
	if err != nil {
		t.Fatalf("read Query response: %v", err)
	}
	root := mustKMIPSuccess(t, response, OperationQuery)
	profiles := allEnumerationValues(root, TagProfileName)
	if !containsEnumeration(profiles, profileSymmetricKeyLifecycleServer14) {
		t.Fatalf("mTLS Query profiles = %v, want Symmetric Key Lifecycle Server 1.4", profiles)
	}
}
