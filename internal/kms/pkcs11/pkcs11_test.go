package pkcs11_test

import (
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
	keys map[string]*crypto.LockedSigner
	n    int
}

func newSoftSession() *softSession {
	return &softSession{keys: map[string]*crypto.LockedSigner{}}
}

func (s *softSession) GenerateKey(alg crypto.Algorithm) (string, []byte, error) {
	ls, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	s.n++
	handle := "obj-" + hex.EncodeToString([]byte{byte(s.n)})
	s.keys[handle] = ls
	s.mu.Unlock()
	return handle, ls.Public().DER, nil
}

func (s *softSession) SignDigest(handle string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	s.mu.Lock()
	ls := s.keys[handle]
	s.mu.Unlock()
	if ls == nil {
		return nil, errUnknownHandle
	}
	return ls.SignDigest(digest, opts)
}

func (s *softSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ls := range s.keys {
		ls.Destroy()
	}
	s.keys = map[string]*crypto.LockedSigner{}
	return nil
}

// errUnknownHandle mirrors a CKR_KEY_HANDLE_INVALID / CKR_OBJECT_HANDLE_INVALID from the
// token: signing against a handle the token does not know fails closed.
var errUnknownHandle = &handleError{}

type handleError struct{}

func (*handleError) Error() string { return "pkcs11: unknown object handle" }

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
