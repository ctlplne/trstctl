// SPDX-License-Identifier: BUSL-1.1

package delegation_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func cr184PersistentSigner(t *testing.T, dir string) *signing.Server {
	t.Helper()
	wrapper, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	srv, err := signing.NewPersistentServer(signing.NewKeyStore(filepath.Join(dir, "keys"), wrapper))
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func cr184IssueAgent(t *testing.T, op *delegation.IssuanceKeyOp, tenant string, nonce byte) error {
	t.Helper()
	binding := delegation.BindingMaterial{
		ChainHeadDigest:   bytes.Repeat([]byte{nonce}, 32),
		AgentStackDigest:  bytes.Repeat([]byte{nonce ^ 0x5a}, 32),
		AgentStackRepr:    []byte("cr184 agent stack"),
		ComparatorVersion: "v1",
	}
	encoded, err := binding.Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, err = op.MintApprovedCredential(t.Context(),
		signing.IssuancePreconditions{TenantID: tenant, TrustAnchorRef: "cr184-agent"},
		signing.IssuanceDecision{Approved: true, BindingMaterial: encoded}, "")
	return err
}

func TestCR184RestartedIssuanceOpRefusesRevokedCachedCA(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	dir := t.TempDir()
	first := cr184PersistentSigner(t, dir)
	firstOp := delegation.NewIssuanceKeyOp(delegation.IssuanceKeyOpConfig{SignerID: "cr184"})
	firstOp.UseSignerCustody(first)
	if err := cr184IssueAgent(t, firstOp, tenant, 1); err != nil {
		t.Fatalf("first boot issuance: %v", err)
	}
	first.Shutdown()

	restarted := cr184PersistentSigner(t, dir)
	defer restarted.Shutdown()
	cachedOp := delegation.NewIssuanceKeyOp(delegation.IssuanceKeyOpConfig{SignerID: "cr184"})
	cachedOp.UseSignerCustody(restarted)
	if err := cr184IssueAgent(t, cachedOp, tenant, 2); err != nil {
		t.Fatalf("restart issuance before revocation: %v", err)
	}
	handle := "agid-issuing-ca-" + tenant
	if _, err := restarted.RevokeKey(context.Background(), &signerpb.RevokeKeyRequest{
		Handle: &signerpb.KeyHandle{Id: handle}, OperationId: "revoke-cr184", Reason: "key_compromise",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cr184IssueAgent(t, cachedOp, tenant, 3); err == nil {
		t.Fatal("restarted AGID op certified another agent with its cached revoked CA")
	}
}
