// SPDX-License-Identifier: BUSL-1.1

package signerwiring_test

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/signerwiring"
)

// The signer can finish a mint while the control plane loses the response or
// fails to record the result. Retrying the same command must return the exact
// sealed result, including after the signer process restarts.
func TestProductionMinterReplaysLostMintResultAcrossRestart(t *testing.T) {
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	dir := t.TempDir()
	boot := func() *signing.Server {
		t.Helper()
		minter, err := signerwiring.NewProductionMinter(signerwiring.Config{FloorDir: dir, JournalWrapper: wrapper})
		if err != nil {
			t.Fatal(err)
		}
		server, err := signing.NewPersistentServer(signing.NewKeyStore(dir, wrapper), signing.WithSuccessionMinter(minter))
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	const tenant = "11111111-1111-1111-1111-111111111111"
	const identity = "spiffe://qa.local/pcas-lost-response"
	server := boot()
	ctx := context.Background()
	predecessor := succession.TenantKeyHandle(tenant, identity, 0)
	if _, err := server.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, RequestedId: predecessor,
	}); err != nil {
		t.Fatalf("generate predecessor: %v", err)
	}
	request := &signerpb.MintSuccessorRequest{
		TenantId: tenant, IdentityId: identity, DeploymentScope: "qa-pcas-lost-response",
		PredecessorHandle: predecessor, AssertedPredecessorEpoch: 0,
		TargetAlgorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P384, PolicyRef: "qa-policy-v1",
	}
	first, err := server.MintSuccessor(ctx, request)
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	if len(first.GetEncodedRecord()) == 0 {
		t.Fatal("first mint returned no record")
	}
	second, err := server.MintSuccessor(ctx, request)
	if err != nil {
		t.Fatalf("lost-response retry: %v", err)
	}
	if !bytes.Equal(second.GetEncodedRecord(), first.GetEncodedRecord()) {
		t.Fatal("lost-response retry returned a different record")
	}
	server = boot()
	third, err := server.MintSuccessor(ctx, request)
	if err != nil {
		t.Fatalf("post-restart retry: %v", err)
	}
	if !bytes.Equal(third.GetEncodedRecord(), first.GetEncodedRecord()) {
		t.Fatal("post-restart retry returned a different record")
	}

	changed := proto.Clone(request).(*signerpb.MintSuccessorRequest)
	changed.PolicyRef = "different-policy"
	if _, err := server.MintSuccessor(ctx, changed); err == nil {
		t.Fatal("changed command reused the prior signer result")
	}
}
