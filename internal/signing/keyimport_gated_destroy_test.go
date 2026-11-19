// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type hierarchyTestGate struct {
	fakeGatedDestroyer
}

func (g *hierarchyTestGate) VerifyGatedDestroyStream(ctx context.Context, req GatedDestroyRequest, evidence io.Reader) (GatedDestroyDecision, error) {
	if _, err := io.Copy(io.Discard, evidence); err != nil {
		return GatedDestroyDecision{}, err
	}
	return g.VerifyGatedDestroy(ctx, req)
}

func TestGatedHierarchyDestructionReturnsRetryableContention(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{{"unary", 128}, {"stream", maxMessageBytes/2 + 1}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImportRecoveryFixture(t)
			var verifications atomic.Int32
			f.signer.gatedDestroyer = &hierarchyTestGate{fakeGatedDestroyer{
				decision: GatedDestroyDecision{Approved: true},
				onCall:   func() { verifications.Add(1) },
			}}
			generateGatedDestroyKey(t, t.Context(), f.signer, f.policy.Handle)
			client := serveHierarchyTestSigner(t, f.signer)
			unlock, err := NewKeyStore(f.store.dir, f.store.wrapper).lockHierarchyCustody(f.policy.Handle)
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			request := GatedDestroyRequest{
				TenantID: "tenant-a", Handle: f.policy.Handle, SubjectRef: "reviewed-ca",
				LedgerPosition: 7, RequiredSetDigest: []byte("reviewed dependency set"),
				SatisfactionEvidence: bytes.Repeat([]byte{'p'}, tc.size),
			}
			_, err = client.GatedDestroy(t.Context(), request)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("gated destruction contention = %v, want Unavailable", err)
			}
			unlock()
			decision, err := client.GatedDestroy(t.Context(), request)
			if err != nil || !decision.Approved || verifications.Load() != 1 {
				t.Fatalf("exact gRPC retry did not recover the authorized destruction: approved=%t, verifications=%d, err=%v", decision.Approved, verifications.Load(), err)
			}
			assertImportName(t, f.store, f.policy.Handle+destroyedKeyFileExt, true)
			assertImportName(t, f.store, f.policy.Handle+keyFileExt, false)
		})
	}
}

func serveHierarchyTestSigner(t *testing.T, server *Server) *Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "trstctl-guard-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ServeServerWithOptions(ctx, socket, server, ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	client, err := DialReady(t.Context(), socket, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}
