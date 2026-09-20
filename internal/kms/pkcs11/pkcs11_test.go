// SPDX-License-Identifier: BUSL-1.1

package pkcs11_test

import (
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/pkcs11"
)

// softSession is a faithful in-process double of a logged-in PKCS#11 token session. It
// performs *real* key generation and signing through the crypto software boundary (locked
// keys, AN-8), so the conformance harness's public-key verification actually passes — the
// same role fakeKMS plays for the AWS KMS backend. No crypto/* is imported here.
type softSession struct {
	mu         sync.Mutex
	keys       map[string]*softKey
	operations map[string]string
	n          int
}

type softKey struct {
	signer   *crypto.LockedSigner
	revoked  bool
	zeroized bool
}

func newSoftSession() *softSession {
	return &softSession{keys: map[string]*softKey{}, operations: map[string]string{}}
}

func (s *softSession) GenerateKey(alg crypto.Algorithm) (string, []byte, error) {
	ls, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	s.n++
	handle := "obj-" + hex.EncodeToString([]byte{byte(s.n)}) // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
	s.keys[handle] = &softKey{signer: ls}
	s.mu.Unlock()
	return handle, ls.Public().DER, nil
}

func (s *softSession) GenerateKeyForOperation(operationID string, alg crypto.Algorithm) (string, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if handle := s.operations[operationID]; handle != "" {
		key := s.keys[handle]
		if key == nil {
			return "", nil, errUnknownHandle
		}
		return handle, key.signer.Public().DER, nil
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("trstctl:pkcs11:managed-key:"+operationID))
	if err != nil {
		return "", nil, err
	}
	ls, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return "", nil, err
	}
	handle := hex.EncodeToString(digest[:16])
	s.n++
	s.keys[handle] = &softKey{signer: ls}
	s.operations[operationID] = handle
	return handle, ls.Public().DER, nil
}

func (s *softSession) SignDigest(handle string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	s.mu.Lock()
	key := s.keys[handle]
	s.mu.Unlock()
	if key == nil {
		return nil, errUnknownHandle
	}
	if key.revoked {
		return nil, errRevokedHandle
	}
	if key.zeroized {
		return nil, errZeroizedHandle
	}
	return key.signer.SignDigest(digest, opts)
}

func (s *softSession) RevokeKey(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.keys[handle]
	if key == nil {
		return errUnknownHandle
	}
	if key.zeroized {
		return errZeroizedHandle
	}
	key.revoked = true
	return nil
}

func (s *softSession) ZeroizeKey(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.keys[handle]
	if key == nil {
		return nil
	}
	key.zeroized = true
	key.signer.Destroy()
	delete(s.keys, handle)
	return nil
}

func (s *softSession) RevokeKeyForOperation(_ string, handle string) error {
	return s.RevokeKey(handle)
}

func (s *softSession) ZeroizeKeyForOperation(_ string, handle string) error {
	return s.ZeroizeKey(handle)
}

func (s *softSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range s.keys {
		key.signer.Destroy()
	}
	s.keys = map[string]*softKey{}
	return nil
}

// errUnknownHandle mirrors a CKR_KEY_HANDLE_INVALID / CKR_OBJECT_HANDLE_INVALID from the
// token: signing against a handle the token does not know fails closed.
var errUnknownHandle = &handleError{}

type handleError struct{}

func (*handleError) Error() string { return "pkcs11: unknown object handle" }

var errRevokedHandle = &stateError{state: "revoked"}
var errZeroizedHandle = &stateError{state: "zeroized"}

type stateError struct{ state string }

func (e *stateError) Error() string { return "pkcs11: key is " + e.state }

func TestPKCS11Conforms(t *testing.T) {
	sess := newSoftSession()
	t.Cleanup(func() { _ = sess.Close() })
	b := pkcs11.New(sess)
	if err := crypto.ConformBackend(b, []crypto.Algorithm{crypto.RSA2048, crypto.ECDSAP256, crypto.ECDSAP384}); err != nil {
		t.Fatalf("PKCS#11 backend failed conformance: %v", err)
	}
}

func TestSignUnknownHandleFails(t *testing.T) {
	sess := newSoftSession()
	t.Cleanup(func() { _ = sess.Close() })

	// Generate a real key so the digest is well-formed, but sign against a handle the
	// token never issued: the operation must fail closed rather than return a signature.
	digest, err := crypto.Digest(crypto.SHA256, []byte("trstctl pkcs11 probe"))
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	sig, err := sess.SignDigest("not-a-real-handle", digest, crypto.SignOptions{Hash: crypto.SHA256})
	if err == nil {
		t.Fatal("SignDigest with a bogus handle returned no error; not fail-closed")
	}
	if sig != nil {
		t.Fatalf("SignDigest returned a signature (%d bytes) for an unknown handle", len(sig))
	}
	if !strings.Contains(err.Error(), "handle") {
		t.Fatalf("error did not identify the bad handle: %v", err)
	}
}

func TestPKCS11RemoteKeyLifecycle(t *testing.T) {
	sess := newSoftSession()
	t.Cleanup(func() { _ = sess.Close() })
	b := pkcs11.New(sess)
	var lc crypto.RemoteKeyLifecycle = b

	ctx := context.Background()
	opts := crypto.SignOptions{Hash: crypto.SHA256}
	msg := []byte("pkcs11 lifecycle probe")

	signer, ref, err := lc.GenerateManagedKey(ctx, crypto.RSA2048)
	if err != nil {
		t.Fatalf("GenerateManagedKey: %v", err)
	}
	if ref.ID == "" || ref.Algorithm != crypto.RSA2048 {
		t.Fatalf("unexpected key ref: %+v", ref)
	}
	sig, err := signer.Sign(msg, opts)
	if err != nil {
		t.Fatalf("sign with generated key: %v", err)
	}
	if err := crypto.Verify(signer.Public(), msg, sig, opts); err != nil {
		t.Fatalf("generated-key signature did not verify: %v", err)
	}

	successor, successorRef, err := lc.RotateKey(ctx, ref)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if successorRef.ID == ref.ID {
		t.Fatalf("rotate returned the same key handle %q", successorRef.ID)
	}
	successorSig, err := successor.Sign(msg, opts)
	if err != nil {
		t.Fatalf("sign with rotated key: %v", err)
	}
	if err := crypto.Verify(successor.Public(), msg, successorSig, opts); err != nil {
		t.Fatalf("rotated-key signature did not verify: %v", err)
	}

	if err := lc.RevokeKey(ctx, ref); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if _, err := signer.Sign(msg, opts); err == nil {
		t.Fatal("revoked PKCS#11 key still signed")
	}

	if err := lc.ZeroizeKey(ctx, successorRef); err != nil {
		t.Fatalf("ZeroizeKey: %v", err)
	}
	if _, err := successor.Sign(msg, opts); err == nil {
		t.Fatal("zeroized PKCS#11 key still signed")
	}
}

func TestPKCS11OperationIdentityReconcilesCreateRevokeAndZeroize(t *testing.T) {
	sess := newSoftSession()
	t.Cleanup(func() { _ = sess.Close() })
	backend := pkcs11.New(sess)
	var lifecycle crypto.OperationAwareRemoteKeyLifecycle = backend
	ctx := context.Background()

	first, firstRef, err := lifecycle.GenerateManagedKeyForOperation(ctx, "pkcs11-create-op", crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	// A fresh backend models signer restart while the token remains authoritative.
	replayed, replayedRef, err := pkcs11.New(sess).GenerateManagedKeyForOperation(ctx, "pkcs11-create-op", crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	if replayedRef != firstRef || sess.n != 1 || !crypto.ConstantTimeEqual(replayed.Public().DER, first.Public().DER) {
		t.Fatalf("create reconciliation refs=%+v/%+v token effects=%d", firstRef, replayedRef, sess.n)
	}
	if err := lifecycle.RevokeKeyForOperation(ctx, "pkcs11-revoke-op", firstRef); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.RevokeKeyForOperation(ctx, "pkcs11-revoke-op", firstRef); err != nil {
		t.Fatalf("reconcile revoke: %v", err)
	}
	if _, err := first.Sign([]byte("revoked"), crypto.SignOptions{Hash: crypto.SHA256}); err == nil {
		t.Fatal("reconciled revoke still signs")
	}

	successor, successorRef, err := lifecycle.RotateKeyForOperation(ctx, "pkcs11-rotate-op", firstRef)
	if err != nil {
		t.Fatal(err)
	}
	replayedSuccessor, replayedSuccessorRef, err := lifecycle.RotateKeyForOperation(ctx, "pkcs11-rotate-op", firstRef)
	if err != nil {
		t.Fatal(err)
	}
	if replayedSuccessorRef != successorRef || sess.n != 2 || !crypto.ConstantTimeEqual(successor.Public().DER, replayedSuccessor.Public().DER) {
		t.Fatalf("rotate reconciliation refs=%+v/%+v token effects=%d", successorRef, replayedSuccessorRef, sess.n)
	}
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "pkcs11-zeroize-op", successorRef); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "pkcs11-zeroize-op", successorRef); err != nil {
		t.Fatalf("reconcile zeroize: %v", err)
	}
	if _, err := successor.Sign([]byte("zeroized"), crypto.SignOptions{Hash: crypto.SHA256}); err == nil {
		t.Fatal("reconciled zeroize still signs")
	}
}
