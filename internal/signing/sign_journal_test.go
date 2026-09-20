// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto/seal"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func TestPersistentSignJournalReplaysExactResultAndRejectsChangedTuple(t *testing.T) {
	wrapper, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x47}, 32))
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	t.Cleanup(wrapper.Destroy)
	dir := t.TempDir()
	keyStore := NewKeyStore(dir, wrapper)
	server, err := NewPersistentServer(keyStore)
	if err != nil {
		t.Fatalf("NewPersistentServer: %v", err)
	}
	ctx := context.Background()
	if _, err := server.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm:       signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId:     "codesign-release",
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CODE_SIGN},
	}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	req := &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: "codesign-release"},
		Digest: bytes.Repeat([]byte{0x11}, 32), Hash: signerpb.Hash_HASH_SHA256,
		Purpose:     signerpb.KeyPurpose_KEY_PURPOSE_CODE_SIGN,
		OperationId: "codesign-operation-1",
	}
	first, err := server.Sign(ctx, req)
	if err != nil {
		t.Fatalf("first Sign: %v", err)
	}
	if first.GetReplayed() || len(first.GetSignature()) == 0 {
		t.Fatalf("first response = %+v, want fresh signature", first)
	}

	// A full signer restart reads the sealed result journal and returns exactly
	// the original randomized ECDSA bytes.
	restarted, err := NewPersistentServer(NewKeyStore(dir, wrapper))
	if err != nil {
		t.Fatalf("restart persistent signer: %v", err)
	}
	replay, err := restarted.Sign(ctx, req)
	if err != nil {
		t.Fatalf("replayed Sign: %v", err)
	}
	if !replay.GetReplayed() || !bytes.Equal(replay.GetSignature(), first.GetSignature()) {
		t.Fatalf("replay differs: replayed=%v first=%x replay=%x", replay.GetReplayed(), first.GetSignature(), replay.GetSignature())
	}

	changed := &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: req.GetHandle().GetId()},
		Digest: bytes.Repeat([]byte{0x22}, 32), Hash: req.GetHash(),
		Purpose: req.GetPurpose(), OperationId: req.GetOperationId(),
	}
	if _, err := restarted.Sign(ctx, changed); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("same operation/different tuple code=%s err=%v, want AlreadyExists", status.Code(err), err)
	}
}

func TestPersistentSignJournalResumesExecutingOperationAfterRestart(t *testing.T) {
	wrapper, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	t.Cleanup(wrapper.Destroy)
	dir := t.TempDir()
	keyStore := NewKeyStore(dir, wrapper)
	server, err := NewPersistentServer(keyStore)
	if err != nil {
		t.Fatalf("NewPersistentServer: %v", err)
	}
	ctx := context.Background()
	if _, err := server.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, RequestedId: "codesign-ephemeral",
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CODE_SIGN},
	}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	req := &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: "codesign-ephemeral"},
		Digest: bytes.Repeat([]byte{0x33}, 32), Hash: signerpb.Hash_HASH_SHA256,
		Purpose:     signerpb.KeyPurpose_KEY_PURPOSE_CODE_SIGN,
		OperationId: "codesign-operation-interrupted",
	}
	if _, replayed, err := keyStore.beginSignOperation(req); err != nil || replayed {
		t.Fatalf("seed executing journal = replayed %v err %v", replayed, err)
	}
	restarted, err := NewPersistentServer(NewKeyStore(dir, wrapper))
	if err != nil {
		t.Fatalf("restart persistent signer: %v", err)
	}
	recovered, err := restarted.Sign(ctx, req)
	if err != nil {
		t.Fatalf("resume executing operation: %v", err)
	}
	if recovered.GetReplayed() || len(recovered.GetSignature()) == 0 {
		t.Fatalf("recovered response=%+v, want newly completed signature", recovered)
	}
	replay, err := restarted.Sign(ctx, req)
	if err != nil {
		t.Fatalf("replay recovered operation: %v", err)
	}
	if !replay.GetReplayed() || !bytes.Equal(replay.GetSignature(), recovered.GetSignature()) {
		t.Fatalf("recovered operation did not persist exact result: recovered=%x replay=%x", recovered.GetSignature(), replay.GetSignature())
	}
}

func TestPersistentSignJournalSerializesConcurrentExactOperation(t *testing.T) {
	wrapper, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	server, err := NewPersistentServer(NewKeyStore(t.TempDir(), wrapper))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := server.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, RequestedId: "codesign-concurrent",
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CODE_SIGN},
	}); err != nil {
		t.Fatal(err)
	}
	request := &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: "codesign-concurrent"},
		Digest: bytes.Repeat([]byte{0x44}, 32), Hash: signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CODE_SIGN, OperationId: "codesign-concurrent-operation",
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var gateOnce sync.Once
	var privateOperations atomic.Int32
	server.signGate = func() {
		privateOperations.Add(1)
		gateOnce.Do(func() { close(entered) })
		<-release
	}
	type result struct {
		response *signerpb.SignResponse
		err      error
	}
	results := make(chan result, 2)
	go func() {
		response, err := server.Sign(ctx, request)
		results <- result{response: response, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first exact operation did not reach private-key execution")
	}
	secondStarted := make(chan struct{})
	go func() {
		close(secondStarted)
		response, err := server.Sign(ctx, request)
		results <- result{response: response, err: err}
	}()
	<-secondStarted
	time.Sleep(50 * time.Millisecond)
	close(release)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent exact operation errors=%v/%v", first.err, second.err)
	}
	if privateOperations.Load() != 1 {
		t.Fatalf("concurrent exact operation reached private signer %d times, want one", privateOperations.Load())
	}
	if !bytes.Equal(first.response.GetSignature(), second.response.GetSignature()) {
		t.Fatalf("concurrent exact responses differ: %x/%x", first.response.GetSignature(), second.response.GetSignature())
	}
	if first.response.GetReplayed() == second.response.GetReplayed() {
		t.Fatalf("concurrent replay flags=%v/%v, want one fresh and one replay", first.response.GetReplayed(), second.response.GetReplayed())
	}
}
