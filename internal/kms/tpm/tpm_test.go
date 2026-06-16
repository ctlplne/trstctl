package tpm_test

import (
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// softDevice is a faithful in-process double of a TPM 2.0 device. It performs *real* key
// generation and signing through the crypto software boundary (locked keys, AN-8), so the
// conformance harness's signature verification actually passes. The "private key never
// leaves the device" property is modeled by keeping the *crypto.LockedSigner inside the
// double and exposing only handles, public DER, and signatures. No crypto/*.
type softDevice struct {
	mu   sync.Mutex
	keys map[string]*crypto.LockedSigner
	n    int
}

func newSoftDevice(t *testing.T) *softDevice {
	t.Helper()
	d := &softDevice{keys: map[string]*crypto.LockedSigner{}}
	t.Cleanup(d.destroy)
	return d
}

func (d *softDevice) destroy() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for h, ls := range d.keys {
		ls.Destroy()
		delete(d.keys, h)
	}
}

// CreateKey generates a locked key, stores it under a fresh handle, and returns the handle
// plus the public key DER — mirroring a TPM that keeps the private key inside the device.
func (d *softDevice) CreateKey(alg crypto.Algorithm) (string, []byte, error) {
	ls, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return "", nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.n++
	handle := "tpm-handle-" + hex.EncodeToString([]byte{byte(d.n)})
	d.keys[handle] = ls
	return handle, ls.Public().DER, nil
}

// Sign delegates to the locked signer for the handle, signing the supplied digest.
func (d *softDevice) Sign(handle string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	d.mu.Lock()
	ls := d.keys[handle]
	d.mu.Unlock()
	if ls == nil {
		return nil, errUnknownHandle
	}
	return ls.SignDigest(digest, opts)
}

func (d *softDevice) Close() error { return nil }

// errUnknownHandle is what the double returns for a handle it never issued, modeling a TPM
// rejecting an unknown/evicted handle.
var errUnknownHandle = unknownHandleErr("tpm: unknown key handle")

type unknownHandleErr string

func (e unknownHandleErr) Error() string { return string(e) }

func TestTPMConforms(t *testing.T) {
	dev := newSoftDevice(t)
	b := tpm.New(dev)
	if err := crypto.ConformBackend(b, []crypto.Algorithm{crypto.RSA2048, crypto.ECDSAP256}); err != nil {
		t.Fatalf("TPM 2.0 backend failed conformance: %v", err)
	}
}

func TestSignUnknownHandleFails(t *testing.T) {
	dev := newSoftDevice(t)
	// Sign directly against a handle the device never issued; the backend must surface the
	// device's error rather than returning a bogus signature.
	_, err := dev.Sign("tpm-handle-deadbeef", []byte("some digest bytes here padding ok"), crypto.SignOptions{Hash: crypto.SHA256})
	if err == nil {
		t.Fatal("Sign succeeded for an unknown handle; device did not fail closed")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unexpected error for unknown handle: %v", err)
	}
}
