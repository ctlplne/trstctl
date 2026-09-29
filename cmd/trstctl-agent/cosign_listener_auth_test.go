// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/agent"
)

func writePredecessorKeyF261(t *testing.T) string {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := key.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "predecessor.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func freeLoopbackAddrF261(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()
	return addr
}

// coSignRun runs the co-sign service for the test and remembers how it ended, so
// a startup refusal can be observed without the cleanup waiting on it again.
type coSignRun struct {
	once  sync.Once
	done  chan error
	err   error
	ended bool
}

func (c *coSignRun) wait(d time.Duration) (error, bool) {
	c.once.Do(func() {
		select {
		case c.err = <-c.done:
			c.ended = true
		case <-time.After(d):
		}
	})
	return c.err, c.ended
}

func startCoSignF261(t *testing.T, cfg workloadCoSignConfig) *coSignRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	run := &coSignRun{done: make(chan error, 1)}
	go func() { run.done <- runWorkloadCoSign(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		if _, ended := run.wait(0); ended {
			return
		}
		select {
		case <-run.done:
		case <-time.After(5 * time.Second):
			t.Error("co-sign service did not stop")
		}
	})
	return run
}

// F261: the co-sign service signs with the workload's predecessor key. A caller
// that cannot authenticate must never obtain a predecessor co-signature over the
// network: either the plain TCP listener refuses to start, or the caller is
// refused before the service answers.
func TestWorkloadCoSignRefusesUnauthenticatedNetworkCaller(t *testing.T) {
	keyPath := writePredecessorKeyF261(t)
	addr := freeLoopbackAddrF261(t)
	const dep, id, tenant = "spiffe://d", "spiffe://d/app", "tenant-a"
	run := startCoSignF261(t, workloadCoSignConfig{
		Listen: addr, DeploymentScope: dep, IdentityID: id, TenantID: tenant, PredecessorKeyPath: keyPath,
	})
	if err, ended := run.wait(500 * time.Millisecond); ended {
		if err == nil || !strings.Contains(err.Error(), "mutual TLS") {
			t.Fatalf("plain TCP co-sign listener stopped with %v; want a refusal naming mutual TLS", err)
		}
		return
	}
	signer, cleanup, err := loadPredecessorSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	attackerSuccessor, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	fields := succession.CommitmentFields{
		DeploymentScope: dep, IdentityID: id, TenantID: tenant,
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: signer.Algorithm(), PredecessorPub: signer.Public().DER,
		PolicyRef: "sha256:attacker", HashAlg: succession.HashAlgSHA256,
		NotBefore: time.Now().Add(-time.Minute).Unix(), NotAfter: time.Now().Add(time.Hour).Unix(),
	}
	rec, err := agent.MintWorkloadHeld(fields, agent.NewRemoteCoSigner(conn).WithContext(ctx), attackerSuccessor)
	if err == nil && succession.VerifyRecord(rec) == nil {
		t.Fatal("an unauthenticated network caller obtained a verifiable predecessor co-signature for a successor key it chose")
	}
}
