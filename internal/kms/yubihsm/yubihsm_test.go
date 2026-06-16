package yubihsm_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/yubihsm"
)

// softConnector is a faithful in-process double of a YubiHSM device. It performs *real*
// key generation and signing via the crypto software boundary (locked keys, AN-8), so the
// conformance harness's signature verification actually passes. Handles are opaque,
// connector-assigned identifiers, exactly as a real device would mint. No crypto/* here —
// the double stays behind the AN-3 boundary just like the production binding will.
type softConnector struct {
	mu   sync.Mutex
	keys map[string]*crypto.LockedSigner
	n    int
}

func newSoftConnector() *softConnector {
	return &softConnector{keys: map[string]*crypto.LockedSigner{}}
}

func (c *softConnector) GenerateKey(alg crypto.Algorithm) (string, []byte, error) {
	ls, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return "", nil, err
	}
	c.mu.Lock()
	c.n++
	handle := fmt.Sprintf("0x%04x", c.n) // opaque device object ID
	c.keys[handle] = ls
	c.mu.Unlock()
	return handle, ls.Public().DER, nil
}

func (c *softConnector) SignDigest(handle string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	c.mu.Lock()
	ls := c.keys[handle]
	c.mu.Unlock()
	if ls == nil {
		// Mirror a device rejecting an unknown object: fail closed.
		return nil, fmt.Errorf("yubihsm device: object %q not found", handle)
	}
	return ls.SignDigest(digest, opts)
}

func (c *softConnector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ls := range c.keys {
		ls.Destroy()
	}
	c.keys = map[string]*crypto.LockedSigner{}
	return nil
}

func TestYubiHSMConforms(t *testing.T) {
	conn := newSoftConnector()
	t.Cleanup(func() { _ = conn.Close() })
	b := yubihsm.New(conn)
	if err := crypto.ConformBackend(b, []crypto.Algorithm{crypto.RSA2048, crypto.ECDSAP256}); err != nil {
		t.Fatalf("YubiHSM backend failed conformance: %v", err)
	}
}

// TestSignUnknownHandleFails proves the backend fails closed when the device rejects the
// key handle (e.g. a deleted or never-created object): Sign must return an error, never a
// silent empty or bogus signature.
func TestSignUnknownHandleFails(t *testing.T) {
	conn := newSoftConnector()
	t.Cleanup(func() { _ = conn.Close() })
	b := yubihsm.New(conn)

	signer, err := b.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Drop the on-device object out from under a live signer handle.
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sig, err := signer.Sign([]byte("payload"), crypto.SignOptions{Hash: crypto.SHA256})
	if err == nil {
		t.Fatal("Sign succeeded against an unknown device handle; backend did not fail closed")
	}
	if len(sig) != 0 {
		t.Fatalf("Sign returned a signature (%d bytes) despite an error", len(sig))
	}
	if !strings.Contains(err.Error(), "yubihsm") {
		t.Fatalf("error not attributed to the backend: %v", err)
	}
}
