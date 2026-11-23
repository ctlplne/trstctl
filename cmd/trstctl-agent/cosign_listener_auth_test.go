// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/agent"
	"trstctl.com/trstctl/internal/succession/minter"
)

func TestCR332ServedWorkloadAgentRequiresEd25519ApprovalOverSocket(t *testing.T) {
	const dep, id, tenant = "spiffe://d", "spiffe://d/app", "tenant-a"
	keyPath := writePredecessorKeyF261(t)
	pred, cleanup, err := loadPredecessorSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	privatePEM, publicPEM, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(privatePEM)
	dir, err := os.MkdirTemp("", "ca")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	pubPath := filepath.Join(dir, "approval.pem")
	if err := os.WriteFile(pubPath, publicPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "agent.sock")
	run := startCoSignF261(t, workloadCoSignConfig{Listen: "unix:" + sock,
		DeploymentScope: dep, IdentityID: id, TenantID: tenant,
		PredecessorKeyPath: keyPath, ApprovalAuthorityFile: pubPath,
		ApprovalStateDir: filepath.Join(dir, "approval-state"), PeerUID: -1})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if err, ended := run.wait(0); ended {
			t.Fatalf("approved co-sign listener stopped: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("approved co-sign listener did not create socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	remote := agent.NewRemoteCoSigner(conn)
	succ, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	fields := succession.CommitmentFields{DeploymentScope: dep, IdentityID: id, TenantID: tenant,
		PredecessorEpoch: 0, Epoch: 1, PredecessorAlg: pred.Algorithm(), PredecessorPub: pred.Public().DER,
		SuccessorAlg: succ.Algorithm(), SuccessorPub: succ.Public().DER,
		PolicyRef: "policy:approved", HashAlg: succession.HashAlgSHA256,
		NotBefore: 1, NotAfter: 1000, CommitmentVersion: 2}
	req := agent.Request{Purpose: agent.Purpose, Fields: fields}
	if _, err := remote.CoSign(req); !errors.Is(err, agent.ErrApproval) {
		t.Fatalf("served agent accepted request without approval: %v", err)
	}
	approvalReq := signing.MintRequest{IdentityID: id, TenantID: tenant,
		DeploymentScope: dep, PredecessorHandle: succession.TenantKeyHandle(tenant, id, 0),
		TargetAlgorithm: succ.Algorithm(), PolicyRef: fields.PolicyRef}
	payload, err := json.Marshal(minter.AuthorizationToken{IdentityID: id, TenantID: tenant,
		PredecessorCustody: succession.PredecessorCustodyWorkload,
		TargetAlgorithm:    succ.Algorithm(), ParamsDigest: minter.RequestParamsDigest(approvalReq), Nonce: "served-workload-approved"})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.SignEd25519(privatePEM, payload)
	if err != nil {
		t.Fatal(err)
	}
	req.Authorization, err = json.Marshal(struct {
		Payload json.RawMessage `json:"payload"`
		Sig     []byte          `json:"sig"`
	}{Payload: payload, Sig: sig})
	if err != nil {
		t.Fatal(err)
	}
	first, err := remote.CoSign(req)
	if err != nil {
		t.Fatalf("served agent rejected valid Ed25519 approval: %v", err)
	}
	second, err := remote.CoSign(req)
	if err != nil || !bytes.Equal(first.Signature, second.Signature) {
		t.Fatalf("served agent did not replay exact saved result: %v", err)
	}
	req.Fields.PolicyRef = "different-policy"
	if _, err := remote.CoSign(req); !errors.Is(err, agent.ErrApproval) {
		t.Fatalf("served agent accepted spent approval for changed commitment: %v", err)
	}
}

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
	if cfg.ApprovalAuthorityFile == "" {
		cfg.ApprovalAuthorityFile, cfg.ApprovalStateDir = testCoSignApprovalF261(t)
	}
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

func testCoSignApprovalF261(t *testing.T) (string, string) {
	t.Helper()
	privatePEM, publicPEM, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(privatePEM)
	dir := t.TempDir()
	path := filepath.Join(dir, "approval.pem")
	if err := os.WriteFile(path, publicPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, dir
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
