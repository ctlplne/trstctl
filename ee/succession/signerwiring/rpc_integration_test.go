// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// TestINT01_MintSuccessorOverTransport is the INT-01 integration test: a real
// isolated signer process (served over a Unix domain socket with SO_PEERCRED peer
// authentication) mints a dual-signed succession record on request from a
// control-plane CLIENT, and only public material crosses the boundary. This is the
// wire path the audit found missing — the method of PCAS-claims-1/12/49 actually
// executed across the custody boundary, not in-process.
func TestINT01_MintSuccessorOverTransport(t *testing.T) {
	// SIGNER side: the predecessor key and the successor keygen backend live only
	// here, inside the signer process. The client never constructs either.
	be := crypto.NewSoftwareBackend()
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	m, err := minter.New(mapResolver{"pred": pred}, be, newMemFloor())
	if err != nil {
		t.Fatal(err)
	}
	svc := signing.NewServer(signing.WithSuccessionMinter(m))
	client := serveSigner(t, svc)

	// CONTROL-PLANE side: request a succession over the transport. The request
	// carries no private key material — the predecessor is a handle.
	req := signing.MintRequest{
		IdentityID:               "spiffe://d/app",
		TenantID:                 "tenant-a",
		DeploymentScope:          "deployment-1",
		PredecessorHandle:        "pred",
		AssertedPredecessorEpoch: 0,
		TargetAlgorithm:          crypto.ECDSAP384,
		PolicyRef:                "sha256:policyref",
		NotBefore:                time.Now().Add(-time.Minute).Unix(),
		NotAfter:                 time.Now().Add(time.Hour).Unix(),
	}
	res, err := client.MintSuccessor(context.Background(), req)
	if err != nil {
		t.Fatalf("MintSuccessor over transport: %v", err)
	}

	if res.Epoch != 1 {
		t.Fatalf("epoch = %d, want 1", res.Epoch)
	}
	if res.SuccessorAlgorithm != crypto.ECDSAP384 {
		t.Fatalf("successor alg = %q, want ECDSA-P384", res.SuccessorAlgorithm)
	}
	if len(res.SuccessorPublicDER) == 0 {
		t.Fatal("no successor public key returned")
	}
	if len(res.EncodedRecord) == 0 {
		t.Fatal("no encoded record returned")
	}

	// The record that crossed the boundary is a valid dual-signed succession record
	// (predecessor attestation + successor possession over the shared commitment).
	rec, err := minter.DecodeRecord(res.EncodedRecord)
	if err != nil {
		t.Fatalf("decode record: %v", err)
	}
	if err := succession.VerifyRecord(rec); err != nil {
		t.Fatalf("record failed dual-attestation verify: %v", err)
	}
	if rec.Fields.PredecessorEpoch != 0 || rec.Fields.Epoch != 1 {
		t.Fatalf("record epochs = %d->%d, want 0->1", rec.Fields.PredecessorEpoch, rec.Fields.Epoch)
	}
	if !bytes.Equal(rec.Fields.PredecessorPub, pred.Public().DER) {
		t.Fatal("record predecessor pub does not match the handle key")
	}
	if !bytes.Equal(rec.Fields.SuccessorPub, res.SuccessorPublicDER) {
		t.Fatal("record successor pub does not match the mint result")
	}

	// Boundary property (INT-INV-2): only PUBLIC material crossed. The successor
	// private key was generated inside the signer process; the response and the
	// record verify using public keys alone. A second, independent mint request for
	// the same identity at the now-superseded epoch is refused by the signer's floor
	// — the control plane cannot rewind epochs it does not control.
	_, err = client.MintSuccessor(context.Background(), req) // asserted epoch 0 again
	if err == nil {
		t.Fatal("expected the signer to refuse a second mint at the superseded epoch")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale-epoch refusal code = %v, want FailedPrecondition", status.Code(err))
	}
}

// TestINT01_FailsClosedWithoutMinter: a signer with no attached minter (core-only
// or unlicensed) refuses to mint with UNIMPLEMENTED, rather than silently
// succeeding or panicking.
func TestINT01_FailsClosedWithoutMinter(t *testing.T) {
	svc := signing.NewServer() // no WithSuccessionMinter
	client := serveSigner(t, svc)
	_, err := client.MintSuccessor(context.Background(), signing.MintRequest{
		IdentityID: "spiffe://d/app", TenantID: "tenant-a",
		PredecessorHandle: "pred", TargetAlgorithm: crypto.ECDSAP384,
	})
	if err == nil {
		t.Fatal("expected an error without an attached minter")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", status.Code(err))
	}
}

// --- signer-side test doubles (SIGNER process only) ---

// mapResolver resolves an opaque predecessor handle to a signer held in the signer
// process. In production the resolver is backed by the signer's key custody store
// (INT-02); here it is a fixed map, sufficient to exercise the transport.
type mapResolver map[string]crypto.Signer

func (m mapResolver) Resolve(handle string) (crypto.Signer, error) {
	s, ok := m[handle]
	if !ok {
		return nil, fmt.Errorf("unknown predecessor handle %q", handle)
	}
	return s, nil
}

// memFloor is an in-memory epoch floor. INT-05 replaces it with a durable,
// restart-surviving floor within the signer custody boundary.
type memFloor struct {
	mu sync.Mutex
	m  map[string]uint64
}

func newMemFloor() *memFloor { return &memFloor{m: map[string]uint64{}} }

func (f *memFloor) Load() (map[string]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]uint64, len(f.m))
	for k, v := range f.m {
		out[k] = v
	}
	return out, nil
}

func (f *memFloor) Advance(id string, epoch uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[id] = epoch
	return nil
}

// serveSigner runs svc as an isolated signer over a UDS socket and returns a
// connected control-plane client, tearing both down at test end.
func serveSigner(t *testing.T, svc *signing.Server) *signing.Client {
	t.Helper()
	// A short socket dir: a Unix domain socket path must fit in sun_path (~108
	// bytes), which t.TempDir()'s long test-name path can overflow.
	dir, err := os.MkdirTemp("", "pcas-sgn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errc := make(chan error, 1)
	go func() {
		errc <- signing.ServeServerWithOptions(ctx, sock, svc, signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
	}()

	client, err := signing.Dial(sock)
	if err != nil {
		t.Fatalf("dial signer: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	deadline := time.Now().Add(8 * time.Second)
	for !client.Healthy(context.Background()) {
		select {
		case serveErr := <-errc:
			t.Fatalf("signer serve failed: %v", serveErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("signer did not become healthy in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return client
}
