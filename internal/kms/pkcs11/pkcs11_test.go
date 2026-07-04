// SPDX-License-Identifier: MPL-2.0

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
	mu   sync.Mutex
	keys map[string]*softKey
	n    int
}

type softKey struct {
	signer   *crypto.LockedSigner
	revoked  bool
	zeroized bool
}

func newSoftSession() *softSession {
	return &softSession{keys: map[string]*softKey{}}
}

func (s *softSession) GenerateKey(alg crypto.Algorithm) (string, []byte, error) {
	ls, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	s.n++
	handle := "obj-" + hex.EncodeToString([]byte{byte(s.n)})
	s.keys[handle] = &softKey{signer: ls}
	s.mu.Unlock()
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
		return errUnknownHandle
	}
	key.zeroized = true
	key.signer.Destroy()
	delete(s.keys, handle)
	return nil
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
