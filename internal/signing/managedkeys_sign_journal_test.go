// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// P9: a managed-key signature bound to an operation id is journaled in the
// signer. A redelivered command — new authorization, same tuple — gets the
// first signature back and the provider signs once; the id cannot sign
// another digest; the journal survives a signer restart; and the
// authorization is still single-use.
func TestManagedKeySignatureIsJournaledByOperation(t *testing.T) {
	provider := newJournalProvider()
	t.Cleanup(provider.cleanup)
	authorizer := managedKeyTestAuthorizer(t)
	dir := t.TempDir()
	newServer := func() *signing.Server {
		return signing.NewServer(
			signing.WithAuthorizer(authorizer),
			signing.WithManagedKeyProviders(dir, map[string]crypto.RemoteKeyLifecycle{"aws-kms": provider}),
		)
	}
	server := newServer()
	created, err := server.ManageKey(context.Background(), &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "create-code-signing-key",
		Action:    signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE,
		Algorithm: signerpb.Algorithm_ALGORITHM_RSA_2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("journaled managed-key signature"))
	if err != nil {
		t.Fatal(err)
	}
	sign := func(s *signing.Server, nonce byte, operationID string, d []byte) (*signerpb.SignManagedKeyResponse, error) {
		req := managedKeyAuthorizedSignRequest(t, authorizer, created.GetKeyId(), d, nonce, time.Now().Add(time.Minute), signing.PurposeCodeSign)
		req.OperationId = operationID
		managedKeyAuthorizeRequest(t, authorizer, req)
		return s.SignManagedKey(context.Background(), req)
	}
	provider.mu.Lock()
	before := provider.sign
	provider.mu.Unlock()
	first, err := sign(server, 40, "codesign-op-1", digest)
	if err != nil || first.GetReplayed() || len(first.GetSignature()) == 0 {
		t.Fatalf("first journaled signature = %+v, %v", first, err)
	}
	if err := crypto.VerifyDigest(crypto.PublicKey{Algorithm: crypto.RSA2048, DER: created.GetPublicKey()}, digest, first.GetSignature(), crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("journaled signature: %v", err)
	}
	again, err := sign(server, 41, "codesign-op-1", digest)
	if err != nil || !again.GetReplayed() || !bytes.Equal(again.GetSignature(), first.GetSignature()) {
		t.Fatalf("redelivered command = %+v, %v", again, err)
	}
	other := bytes.Clone(digest)
	other[0] ^= 0x01
	if _, err := sign(server, 42, "codesign-op-1", other); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("the operation id signed another digest: %v", err)
	}
	restarted := newServer()
	afterRestart, err := sign(restarted, 43, "codesign-op-1", digest)
	if err != nil || !afterRestart.GetReplayed() || !bytes.Equal(afterRestart.GetSignature(), first.GetSignature()) {
		t.Fatalf("after a signer restart = %+v, %v", afterRestart, err)
	}
	provider.mu.Lock()
	signs := provider.sign - before
	provider.mu.Unlock()
	if signs != 1 {
		t.Fatalf("the provider signed %d times for one command", signs)
	}
	replayedToken := managedKeyAuthorizedSignRequest(t, authorizer, created.GetKeyId(), digest, 43, time.Now().Add(time.Minute), signing.PurposeCodeSign)
	replayedToken.OperationId = "codesign-op-1"
	managedKeyAuthorizeRequest(t, authorizer, replayedToken)
	if _, err := restarted.SignManagedKey(context.Background(), replayedToken); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a used authorization read the journal again: %v", err)
	}
	if plain, err := sign(restarted, 44, "", digest); err != nil || plain.GetReplayed() {
		t.Fatalf("an unjournaled signature = %+v, %v", plain, err)
	}
}
