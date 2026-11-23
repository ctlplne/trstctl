// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/crypto"
)

func TestCR297OperatorProvisionsExactSignerLocalTrust(t *testing.T) {
	floor := filepath.Join(t.TempDir(), "signer-floor")
	publicDER, _, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherDER, _, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	write := func(binding agentTrustBinding) string {
		t.Helper()
		raw, err := json.Marshal(binding)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "binding.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, binding := range []agentTrustBinding{
		{Kind: "root_anchor", TenantID: "tenant-a", KeyID: "root-a", AuthRef: "fido2:operator", PublicKeyPEM: string(crypto.MarshalPublicKeyPEM(publicDER))},
		{Kind: "attestor", TenantID: "tenant-a", KeyID: "attestor-a", Method: "tpm", PublicKeyPEM: string(crypto.MarshalPublicKeyPEM(publicDER))},
		{Kind: "reachability_key", KeyID: "reach-a", PublicKeyPEM: string(crypto.MarshalPublicKeyPEM(publicDER))},
	} {
		path := write(binding)
		for retry := 0; retry < 2; retry++ {
			if err := runAgentTrustProvision(path, floor); err != nil {
				t.Fatalf("%s operator provision retry %d: %v", binding.Kind, retry, err)
			}
		}
		binding.PublicKeyPEM = string(crypto.MarshalPublicKeyPEM(otherDER))
		if err := runAgentTrustProvision(write(binding), floor); err == nil {
			t.Fatalf("%s changed first writer was accepted", binding.Kind)
		}
	}
	ctx := context.Background()
	rootDER, authRef, err := delegation.NewDurableAnchorStore(floor).ReadAgentRootAnchor(ctx, "tenant-a", "root-a")
	if err != nil || !bytes.Equal(rootDER, publicDER) || authRef != "fido2:operator" {
		t.Fatalf("root readback: auth=%q err=%v", authRef, err)
	}
	attestorDER, method, err := delegation.NewDurableAttestationTrustStore(floor).ReadAgentAttestor(ctx, "tenant-a", "attestor-a")
	if err != nil || !bytes.Equal(attestorDER, publicDER) || method != "tpm" {
		t.Fatalf("attestor readback: method=%q err=%v", method, err)
	}
	reachDER, err := delegation.NewDurableReachabilityTrustStore(floor).ReadVerdictSigner(ctx, "reach-a")
	if err != nil || !bytes.Equal(reachDER, publicDER) {
		t.Fatalf("reachability readback: err=%v", err)
	}
	if err := runAgentTrustProvision(write(agentTrustBinding{Kind: "root_anchor", TenantID: "tenant-a", KeyID: "root-b", Method: "tpm", PublicKeyPEM: string(crypto.MarshalPublicKeyPEM(publicDER))}), floor); err == nil {
		t.Fatal("invalid mixed-kind trust binding was accepted")
	}
}
