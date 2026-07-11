// SPDX-License-Identifier: MPL-2.0

package tpm_test

import (
	"context"
	"encoding/binary"
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
	mu            sync.Mutex
	keys          map[string]*crypto.LockedSigner
	operations    map[string]string
	operationTags map[string][]byte
	removals      int
	n             int
}

func newSoftDevice(t *testing.T) *softDevice {
	t.Helper()
	d := &softDevice{
		keys: map[string]*crypto.LockedSigner{}, operations: map[string]string{}, operationTags: map[string][]byte{},
	}
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

func (d *softDevice) CreateKeyForOperation(operationID string, alg crypto.Algorithm) (string, []byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tag, err := crypto.Digest(crypto.SHA256, []byte("trstctl:tpm2:managed-key:"+operationID))
	if err != nil {
		return "", nil, err
	}
	// Read every persistent public tag before choosing a free deterministic
	// probe. This models the real GetCapability + ReadPublic reconciliation.
	for handle, existingTag := range d.operationTags {
		if crypto.ConstantTimeEqual(existingTag, tag) {
			key := d.keys[handle]
			if key == nil {
				return "", nil, errUnknownHandle
			}
			d.operations[operationID] = handle
			return handle, key.Public().DER, nil
		}
	}
	const (
		minHandle = uint64(0x81010100)
		maxHandle = uint64(0x81ffffff)
	)
	rangeSize := maxHandle - minHandle + 1
	start := binary.BigEndian.Uint64(tag[:8]) % rangeSize
	var handle string
	for probe := uint64(0); probe < rangeSize; probe++ {
		handle = "0x" + hex.EncodeToString([]byte{
			byte((minHandle + ((start + probe) % rangeSize)) >> 24),
			byte((minHandle + ((start + probe) % rangeSize)) >> 16),
			byte((minHandle + ((start + probe) % rangeSize)) >> 8),
			byte(minHandle + ((start + probe) % rangeSize)),
		})
		if d.keys[handle] == nil {
			break
		}
	}
	ls, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return "", nil, err
	}
	d.n++
	d.keys[handle] = ls
	d.operations[operationID] = handle
	d.operationTags[handle] = append([]byte(nil), tag...)
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

func (d *softDevice) RevokeKey(handle string) error  { return d.remove(handle) }
func (d *softDevice) ZeroizeKey(handle string) error { return d.remove(handle) }

func (d *softDevice) RevokeKeyForOperation(_ string, handle string) error {
	return d.remove(handle)
}

func (d *softDevice) ZeroizeKeyForOperation(_ string, handle string) error {
	return d.remove(handle)
}

func (d *softDevice) remove(handle string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if key := d.keys[handle]; key != nil {
		key.Destroy()
		delete(d.keys, handle)
		delete(d.operationTags, handle)
		d.removals++
	}
	return nil
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

func TestTPMOperationIdentityReconcilesPersistentCreateAndRemoval(t *testing.T) {
	device := newSoftDevice(t)
	backend := tpm.New(device)
	var lifecycle crypto.OperationAwareRemoteKeyLifecycle = backend
	ctx := context.Background()

	first, firstRef, err := lifecycle.GenerateManagedKeyForOperation(ctx, "tpm-create-op", crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	replayed, replayedRef, err := tpm.New(device).GenerateManagedKeyForOperation(ctx, "tpm-create-op", crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if replayedRef != firstRef || device.n != 1 || !crypto.ConstantTimeEqual(first.Public().DER, replayed.Public().DER) {
		t.Fatalf("persistent create reconciliation refs=%+v/%+v device effects=%d", firstRef, replayedRef, device.n)
	}
	if err := lifecycle.RevokeKeyForOperation(ctx, "tpm-revoke-op", firstRef); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.RevokeKeyForOperation(ctx, "tpm-revoke-op", firstRef); err != nil {
		t.Fatalf("reconcile revoke removal: %v", err)
	}
	if device.removals != 1 {
		t.Fatalf("replayed TPM revoke removal effects=%d, want one", device.removals)
	}
	if _, err := first.Sign([]byte("revoked"), crypto.SignOptions{Hash: crypto.SHA256}); err == nil {
		t.Fatal("reconciled TPM revoke still signs")
	}

	successor, successorRef, err := lifecycle.RotateKeyForOperation(ctx, "tpm-rotate-op", firstRef)
	if err != nil {
		t.Fatal(err)
	}
	replayedSuccessor, replayedSuccessorRef, err := lifecycle.RotateKeyForOperation(ctx, "tpm-rotate-op", firstRef)
	if err != nil {
		t.Fatal(err)
	}
	if replayedSuccessorRef != successorRef || device.n != 2 || !crypto.ConstantTimeEqual(successor.Public().DER, replayedSuccessor.Public().DER) {
		t.Fatalf("persistent rotate reconciliation refs=%+v/%+v device effects=%d", successorRef, replayedSuccessorRef, device.n)
	}
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "tpm-zeroize-op", successorRef); err != nil {
		t.Fatal(err)
	}
	if device.removals != 2 {
		t.Fatalf("replayed TPM zeroize removal effects=%d, want one additional removal", device.removals)
	}
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "tpm-zeroize-op", successorRef); err != nil {
		t.Fatalf("reconcile zeroize removal: %v", err)
	}
	if _, err := successor.Sign([]byte("zeroized"), crypto.SignOptions{Hash: crypto.SHA256}); err == nil {
		t.Fatal("reconciled TPM zeroize still signs")
	}
}

func TestTPMOperationIdentityProbesPastForeignSameAlgorithmHandle(t *testing.T) {
	device := newSoftDevice(t)
	const operationID = "tpm-forced-foreign-collision"
	tag, err := crypto.Digest(crypto.SHA256, []byte("trstctl:tpm2:managed-key:"+operationID))
	if err != nil {
		t.Fatal(err)
	}
	const (
		minHandle = uint64(0x81010100)
		maxHandle = uint64(0x81ffffff)
	)
	firstValue := minHandle + (binary.BigEndian.Uint64(tag[:8]) % (maxHandle - minHandle + 1))
	firstHandle := "0x" + hex.EncodeToString([]byte{byte(firstValue >> 24), byte(firstValue >> 16), byte(firstValue >> 8), byte(firstValue)})
	foreign, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	device.keys[firstHandle] = foreign
	device.operationTags[firstHandle] = []byte("foreign-full-operation-tag")
	foreignPublic := append([]byte(nil), foreign.Public().DER...)

	created, ref, err := tpm.New(device).GenerateManagedKeyForOperation(context.Background(), operationID, crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID == firstHandle {
		t.Fatalf("operation silently bound foreign same-algorithm handle %q", firstHandle)
	}
	if device.keys[firstHandle] != foreign || !crypto.ConstantTimeEqual(device.keys[firstHandle].Public().DER, foreignPublic) {
		t.Fatal("foreign persistent object was overwritten while probing")
	}
	replayed, replayedRef, err := tpm.New(device).GenerateManagedKeyForOperation(context.Background(), operationID, crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if replayedRef != ref || !crypto.ConstantTimeEqual(replayed.Public().DER, created.Public().DER) || device.n != 1 {
		t.Fatalf("collision restart refs=%+v/%+v provider effects=%d", ref, replayedRef, device.n)
	}
}
