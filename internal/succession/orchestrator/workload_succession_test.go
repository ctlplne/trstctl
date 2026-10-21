// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/agent"
	"trstctl.com/trstctl/internal/succession/minter"
	"trstctl.com/trstctl/internal/succession/orchestrator"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
	"trstctl.com/trstctl/internal/translog"
)

// softwareCustody stands in for the isolated signer's key custody with
// software keys: the tenant trust root and per-epoch successor handles.
type softwareCustody struct {
	keys map[string]crypto.Signer
}

func (c *softwareCustody) SignerForHandle(_ context.Context, handle string) (crypto.Signer, error) {
	if s, ok := c.keys[handle]; ok {
		return s, nil
	}
	return nil, status.Error(codes.NotFound, "no such handle")
}

func (c *softwareCustody) GenerateKeyHandle(_ context.Context, algorithm crypto.Algorithm, handle string) (crypto.Signer, error) {
	if _, ok := c.keys[handle]; ok {
		return nil, status.Error(codes.AlreadyExists, "handle exists")
	}
	s, err := crypto.NewSoftwareBackend().GenerateKey(algorithm)
	if err != nil {
		return nil, err
	}
	c.keys[handle] = s
	return s, nil
}

// A workload-held identity's first succession is minted through the agent's
// co-sign RPC: the control plane never holds the predecessor key, the successor
// is generated in custody, the record carries a tenant-root inclusion proof,
// the chain verifies offline, and a redelivery of the same request mints
// nothing more.
func TestWorkloadHeldSuccessionCoSignsThroughAgent(t *testing.T) {
	ctx := context.Background()
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cs.Close)
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	repo := pcasstore.New(cs)
	const identity = "spiffe://qa.local/workload/cosign"
	const scope = "spiffe://qa.local"

	// The workload agent holds the predecessor key and serves co-sign on an
	// owner-only unix socket.
	workloadKey, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	cosigner, err := agent.New(agent.Config{DeploymentScope: scope, IdentityID: identity, TenantID: tenantA, Signer: workloadKey})
	if err != nil {
		t.Fatal(err)
	}
	// A unix socket path is capped at 104 bytes on macOS; t.TempDir() embeds the
	// long test name, so the socket lives in a short sibling directory.
	sockDir, err := os.MkdirTemp(os.TempDir(), "cs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "cosign.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	agent.NewCoSignServer(cosigner).Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	// Genesis anchors the workload's public key under the tenant trust root.
	custody := &softwareCustody{keys: map[string]crypto.Signer{}}
	root, err := custody.GenerateKeyHandle(ctx, crypto.ECDSAP256, succession.TenantRootHandle(tenantA))
	if err != nil {
		t.Fatal(err)
	}
	genesis := succession.GenesisRecord{
		DeploymentScope: scope, IdentityID: identity, TenantID: tenantA, Algorithm: crypto.ECDSAP256,
		PublicKey: workloadKey.Public().DER, Epoch: 0, PredecessorCustody: succession.PredecessorCustodyWorkload,
	}
	digest, err := succession.GenesisDigest(genesis)
	if err != nil {
		t.Fatal(err)
	}
	genesis.TrustRootAtt, err = root.Sign(digest, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	if err := succession.VerifyGenesis(root.Public().DER, genesis); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutGenesis(ctx, tenantA, pcasstore.GenesisAnchor{Genesis: genesis, TrustRootPublicDER: root.Public().DER, EventID: "genesis-ev", RequestID: "genesis-req"}); err != nil {
		t.Fatal(err)
	}

	dialer := orchestrator.NewConfiguredWorkloadCoSigners([]orchestrator.WorkloadCoSignerEndpoint{{TenantID: tenantA, IdentityID: identity, Address: "unix:" + sock}})
	worker := orchestrator.NewSuccessionRequestWorker(orchestrator.New(cs, nil)).WithWorkloadCoSign(custody, dialer)
	payload, _ := json.Marshal(map[string]any{
		"request_id": "workload-succession-1", "identity_id": identity, "credential_type": "x509",
		"target_algorithm": string(crypto.ECDSAP384), "policy_ref": "policy:workload", "deployment_scope": scope,
		"predecessor_custody": "workload",
	})
	if err := worker.Handle(ctx, tenantA, payload); err != nil {
		t.Fatalf("workload-held succession: %v", err)
	}
	chain, err := repo.FetchChain(ctx, tenantA, identity)
	if err != nil || len(chain) != 1 {
		t.Fatalf("chain len=%d err=%v", len(chain), err)
	}
	rec, err := minter.DecodeRecord(chain[0].Encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.Fields.PredecessorPub, workloadKey.Public().DER) || rec.Fields.Epoch != 1 || rec.Fields.SuccessorAlg != crypto.ECDSAP384 {
		t.Fatalf("record fields: %+v", rec.Fields)
	}
	if _, held := custody.keys[succession.TenantKeyHandle(tenantA, identity, 1)]; !held {
		t.Fatal("the successor key was not generated in custody")
	}
	if _, leaked := custody.keys[succession.TenantKeyHandle(tenantA, identity, 0)]; leaked {
		t.Fatal("custody holds a predecessor key it must never have")
	}
	commitment, err := succession.Commit(rec.Fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.VerifyWorkloadHeld(rec, func(proof []byte) error {
		return translog.VerifyEncodedInclusion(commitment, proof, root.Public().DER)
	}); err != nil {
		t.Fatalf("relying-party verification of the workload-held record: %v", err)
	}
	if err := succession.VerifyChain(genesis, []succession.SuccessionRecord{rec}, 0); err != nil {
		t.Fatalf("chain verification: %v", err)
	}
	if epoch, found, err := repo.GetHighWater(ctx, tenantA, identity); err != nil || !found || epoch != 1 {
		t.Fatalf("high-water: epoch=%d found=%v err=%v", epoch, found, err)
	}
	// Redelivery of the same request mints nothing more.
	if err := worker.Handle(ctx, tenantA, payload); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if chain, err := repo.FetchChain(ctx, tenantA, identity); err != nil || len(chain) != 1 {
		t.Fatalf("redelivery changed the chain: len=%d err=%v", len(chain), err)
	}
	// The agent refuses a commitment that is not its own identity: a request for
	// another identity anchored to the same socket cannot obtain a signature.
	otherDialer := orchestrator.NewConfiguredWorkloadCoSigners([]orchestrator.WorkloadCoSignerEndpoint{{TenantID: tenantA, IdentityID: "spiffe://qa.local/workload/other", Address: "unix:" + sock}})
	otherGenesis := genesis
	otherGenesis.IdentityID = "spiffe://qa.local/workload/other"
	otherDigest, _ := succession.GenesisDigest(otherGenesis)
	otherGenesis.TrustRootAtt, _ = root.Sign(otherDigest, crypto.SignOptions{Hash: crypto.SHA256})
	if err := repo.PutGenesis(ctx, tenantA, pcasstore.GenesisAnchor{Genesis: otherGenesis, TrustRootPublicDER: root.Public().DER, EventID: "genesis-ev-2", RequestID: "genesis-req-2"}); err != nil {
		t.Fatal(err)
	}
	otherWorker := orchestrator.NewSuccessionRequestWorker(orchestrator.New(cs, nil)).WithWorkloadCoSign(custody, otherDialer)
	otherPayload, _ := json.Marshal(map[string]any{
		"request_id": "workload-succession-other", "identity_id": "spiffe://qa.local/workload/other", "credential_type": "x509",
		"target_algorithm": string(crypto.ECDSAP384), "policy_ref": "policy:workload", "deployment_scope": scope,
	})
	if err := otherWorker.Handle(ctx, tenantA, otherPayload); err == nil || !strings.Contains(err.Error(), "refus") {
		t.Fatalf("agent must refuse a foreign identity's commitment: %v", err)
	}
	// Without a configured co-signer the workload-held path fails closed.
	bare := orchestrator.NewSuccessionRequestWorker(orchestrator.New(cs, nil)).WithWorkloadCoSign(custody, orchestrator.NewConfiguredWorkloadCoSigners(nil))
	if err := bare.Handle(ctx, tenantA, otherPayload); err == nil || !strings.Contains(err.Error(), "no workload co-signer") {
		t.Fatalf("missing co-signer must fail closed: %v", err)
	}
}
