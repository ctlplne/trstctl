// SPDX-License-Identifier: MPL-2.0

package workloadapi_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"trstctl.com/trstctl/internal/agent/workloadapi"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

// The Workload API, served on the host, with the key born there (epic B3).
//
// The property that matters is not that a response comes back — it is WHERE the
// private key was made. A workload's SVID key is the thing that makes it that
// workload, and before this epic it was generated on the control plane and
// shipped over the network to a machine it had never been on.

// recordingUpstream is a control plane that records what the host sent up.
type recordingUpstream struct {
	gotPublicKey []byte
	gotSelectors []string
	gotAudience  []string
	svids        *workloadapi.SVIDSet
	err          error
}

func (r *recordingUpstream) FetchWorkloadSVID(
	_ context.Context, publicKeyDER []byte, selectors, audience []string,
) (*workloadapi.SVIDSet, error) {
	r.gotPublicKey = append([]byte(nil), publicKeyDER...)
	r.gotSelectors = append([]string(nil), selectors...)
	r.gotAudience = append([]string(nil), audience...)
	return r.svids, r.err
}

func dialWorkloadAPI(t *testing.T, up workloadapi.Upstream) workloadpb.SpiffeWorkloadAPIClient {
	t.Helper()
	// A SHORT path, not t.TempDir(). A unix socket path is capped near 104
	// bytes by the kernel, and t.TempDir() embeds the full test name — which for
	// tests named after the property they check runs well past the limit and
	// fails as "socket never came up" rather than as "path too long".
	socket := shortSocketPath(t)
	srv := workloadapi.New(up, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, socket) }()
	t.Cleanup(func() { cancel(); <-done })

	// Wait for the socket to appear rather than sleeping a fixed interval. The
	// probe connection is CLOSED: a half-open connection left dangling here
	// would be accepted by the server and then block its graceful shutdown.
	deadline := time.Now().Add(5 * time.Second)
	for {
		probe, err := net.Dial("unix", socket)
		if err == nil {
			_ = probe.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the workload API socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := grpc.NewClient("unix:"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return workloadpb.NewSpiffeWorkloadAPIClient(conn)
}

// shortSocketPath returns a unix socket path inside the kernel's length limit.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "w.sock")
	if len(path) > 100 {
		t.Skipf("socket path %q is too long for this platform's unix socket limit", path)
	}
	return path
}

func workloadCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return metadata.AppendToOutgoingContext(ctx, workloadapi.SecurityHeaderKey, workloadapi.SecurityHeaderValue)
}

// The key is generated on this host: only a PUBLIC key goes up, and the private
// half comes back to the workload without ever having been on the network.
func TestTheSVIDKeyIsGeneratedOnTheHostAndOnlyThePublicHalfTravels(t *testing.T) {
	t.Parallel()
	leaf := selfSignedLeafDER(t)
	up := &recordingUpstream{svids: &workloadapi.SVIDSet{
		X509: []workloadapi.X509SVID{{
			SPIFFEID: "spiffe://example.org/payments", CertChainDER: [][]byte{leaf},
		}},
		Bundle: [][]byte{leaf},
	}}
	client := dialWorkloadAPI(t, up)

	stream, err := client.FetchX509SVID(workloadCtx(t), &workloadpb.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if len(resp.Svids) != 1 {
		t.Fatalf("got %d SVIDs, want 1", len(resp.Svids))
	}

	// What went UP must be a public key and nothing else.
	if len(up.gotPublicKey) == 0 {
		t.Fatal("no public key was sent up, so the control plane signed nothing this host made")
	}
	if !crypto.IsPKIXPublicKey(up.gotPublicKey) {
		t.Error("what travelled up is not a PKIX public key")
	}
	if crypto.IsPKCS8PrivateKey(up.gotPublicKey) {
		t.Error("a PRIVATE key travelled up; only the public half may leave the host that " +
			"generated it, and that is the entire security claim of moving the Workload API here")
	}
	for _, marker := range [][]byte{[]byte("PRIVATE KEY"), []byte("-----BEGIN")} {
		if bytes.Contains(up.gotPublicKey, marker) {
			t.Errorf("the material sent up contains %q; only a public key may leave this host", marker)
		}
	}

	// What came back to the WORKLOAD must include the private key — generated
	// here, never received from the network.
	svid := resp.Svids[0]
	if len(svid.X509SvidKey) == 0 {
		t.Fatal("the workload received no private key, so it cannot use its own SVID")
	}
	if !crypto.IsPKCS8PrivateKey(svid.X509SvidKey) {
		t.Error("the key handed to the workload is not a PKCS#8 private key")
	}
}

// The selectors are the kernel's observation of THIS process, not anything the
// caller said.
func TestTheHostAttestsItsCallerRatherThanTrustingIt(t *testing.T) {
	t.Parallel()
	leaf := selfSignedLeafDER(t)
	up := &recordingUpstream{svids: &workloadapi.SVIDSet{
		X509:   []workloadapi.X509SVID{{SPIFFEID: "spiffe://example.org/w", CertChainDER: [][]byte{leaf}}},
		Bundle: [][]byte{leaf},
	}}
	client := dialWorkloadAPI(t, up)

	stream, err := client.FetchX509SVID(workloadCtx(t), &workloadpb.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("recv: %v", err)
	}

	// This test process connected, so the selectors must describe it.
	var sawUnix, sawUID bool
	for _, sel := range up.gotSelectors {
		if sel == "unix" {
			sawUnix = true
		}
		if len(sel) > len("unix:uid:") && sel[:len("unix:uid:")] == "unix:uid:" {
			sawUID = true
		}
	}
	if !sawUnix || !sawUID {
		t.Fatalf("selectors = %v; the host must report what the kernel says about the calling "+
			"process, and a uid is the minimum any platform can offer", up.gotSelectors)
	}
}

// The mandatory SPIFFE security header is enforced, so an ambient gRPC client
// that wandered onto the socket is not treated as a workload asking for an
// identity.
func TestARequestWithoutTheSecurityHeaderIsRefused(t *testing.T) {
	t.Parallel()
	client := dialWorkloadAPI(t, &recordingUpstream{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workloadpb.X509SVIDRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil {
		t.Fatal("a request with no SPIFFE security header was served")
	}
}

// A JWT-SVID request generates no key at all — the token is signed by the trust
// domain's JWT authority — and must not send a phantom public key up.
func TestAJWTRequestSendsNoKeyUp(t *testing.T) {
	t.Parallel()
	up := &recordingUpstream{svids: &workloadapi.SVIDSet{
		JWT: []workloadapi.JWTSVID{{SPIFFEID: "spiffe://example.org/w", Token: "header.payload.sig"}},
	}}
	client := dialWorkloadAPI(t, up)

	resp, err := client.FetchJWTSVID(workloadCtx(t), &workloadpb.JWTSVIDRequest{
		Audience: []string{"https://api.example.test"},
	})
	if err != nil {
		t.Fatalf("FetchJWTSVID: %v", err)
	}
	if len(resp.Svids) != 1 || resp.Svids[0].Svid != "header.payload.sig" {
		t.Fatalf("jwt response = %+v", resp.Svids)
	}
	if len(up.gotPublicKey) != 0 {
		t.Errorf("a JWT request sent a public key up (%d bytes); nothing is generated for a "+
			"JWT-SVID, so sending one would imply a key that does not exist", len(up.gotPublicKey))
	}
	if len(up.gotAudience) != 1 {
		t.Errorf("audience did not reach the control plane: %v", up.gotAudience)
	}
}

// selfSignedLeafDER is a stand-in certificate.
//
// The control plane is faked in these tests, so the certificate's contents do
// not matter — what is under test is where the KEY was made, not what the CA
// signed. Built through internal/crypto (AN-3) rather than crypto/x509 directly.
func selfSignedLeafDER(t *testing.T) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := crypto.SelfSignedCACert(key, "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
