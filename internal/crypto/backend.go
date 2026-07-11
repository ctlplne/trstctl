// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	"context"
	"fmt"
)

// S9.1 — the KMS/HSM backend template. A Backend is a key-management backend behind
// the AN-3 boundary: it names itself and generates keys (as a KeyGenerator). The
// software backend, an HSM (PKCS#11, TPM 2.0, YubiHSM), and a cloud KMS (AWS/Azure/GCP)
// each implement this one interface, so adding a backend is a single package change and
// swapping one for another needs no caller changes. Every backend self-validates by
// passing ConformBackend, the conformance harness below.

// Backend is a key-management backend.
type Backend interface {
	// Name identifies the backend, for diagnostics and inventory.
	Name() string
	KeyGenerator
}

var _ Backend = (*SoftwareBackend)(nil)

// KeyRef identifies a key held by a remote backend (an HSM/KMS) without exposing
// any private material. It is the handle a backend returns from GenerateManagedKey
// and accepts in the lifecycle operations below.
type KeyRef struct {
	// ID is the backend-native key identifier (e.g. a KMS key id/ARN, an HSM
	// object handle). It is not secret.
	ID string
	// Algorithm is the key's signature algorithm.
	Algorithm Algorithm
}

// RemoteKeyLifecycle is the BYOK/HSM key-lifecycle contract for backends whose
// keys live OUTSIDE this process — a cloud KMS or a networked HSM where the
// private key never materializes in the control-plane address space at all
// (EXC-CRYPTO-01). For these backends "zeroize" is not a local buffer wipe: the
// material is destroyed by the provider, so the lifecycle is expressed as remote
// operations the provider performs on the operator's behalf:
//
//   - RotateKey mints a successor key and returns a Signer for it (the caller
//     re-points issuance at the new key);
//   - RevokeKey disables the key so the provider refuses further signatures with
//     it (fail-closed at the device);
//   - ZeroizeKey schedules/performs the provider's destruction of the key material.
//
// A backend implements this when its provider exposes the operations; the
// in-process SoftwareBackend does not (its lifecycle is the local secret.Buffer
// path in internal/crypto/byok). Callers detect support with a type assertion.
// Each method takes a context so the remote round-trip is cancelable/deadline-
// bound (CODE-002), exactly like ContextSigner.
type RemoteKeyLifecycle interface {
	// GenerateManagedKey creates a key in the backend and returns both a Signer to
	// use it and a KeyRef to manage its lifecycle. The private key never leaves the
	// backend.
	GenerateManagedKey(ctx context.Context, algorithm Algorithm) (Signer, KeyRef, error)
	// RotateKey mints a successor to ref and returns a Signer for the new key. The
	// old key is left intact (the caller revokes/zeroizes it once re-pointed).
	RotateKey(ctx context.Context, ref KeyRef) (Signer, KeyRef, error)
	// RevokeKey disables ref so the backend refuses further signatures with it.
	RevokeKey(ctx context.Context, ref KeyRef) error
	// ZeroizeKey schedules/performs destruction of ref's key material in the backend.
	ZeroizeKey(ctx context.Context, ref KeyRef) error
}

// OperationAwareRemoteKeyLifecycle is the crash-reconciling extension used by
// the isolated signer for served managed-key commands. operationID is the
// durable command identity written to the signer journal before provider I/O.
// Repeating any method with the same operationID and command MUST find or
// reconcile the original provider effect; it must never create a second key or
// repeat an unsafe destructive transition.
//
// RemoteKeyLifecycle remains the library contract for callers that do not own a
// durable operation identity. Shipped signer providers implement both contracts;
// the signer prefers this one whenever it is available.
type OperationAwareRemoteKeyLifecycle interface {
	// GenerateManagedKeyForOperation creates or finds the key deterministically
	// owned by operationID.
	GenerateManagedKeyForOperation(ctx context.Context, operationID string, algorithm Algorithm) (Signer, KeyRef, error)
	// RotateKeyForOperation creates or finds the successor deterministically owned
	// by operationID while leaving ref intact.
	RotateKeyForOperation(ctx context.Context, operationID string, ref KeyRef) (Signer, KeyRef, error)
	// RevokeKeyForOperation ensures ref is disabled/retired and confirms provider
	// state when operationID is replayed.
	RevokeKeyForOperation(ctx context.Context, operationID string, ref KeyRef) error
	// ZeroizeKeyForOperation ensures provider destruction is scheduled/completed
	// and confirms that terminal state when operationID is replayed.
	ZeroizeKeyForOperation(ctx context.Context, operationID string, ref KeyRef) error
}

// RemoteKeyDigestSigner is the signer-process-only operation for an existing
// provider key reference. Implementations must perform the private-key
// operation at the provider/device and return only the signature.
type RemoteKeyDigestSigner interface {
	SignManagedDigest(ctx context.Context, ref KeyRef, digest []byte, opts SignOptions) ([]byte, error)
}

// ConformBackend is the backend conformance harness. For each algorithm it generates a
// key, signs a probe message, verifies the signature against the returned public key,
// confirms the reported algorithm, and confirms that a wrong message and a tampered
// signature both fail closed. A backend that passes behaves indistinguishably from the
// software reference at the boundary — the same role ConformDNSProvider/connector
// conformance play for their plugins. It performs only public-key verification itself,
// so it never needs a second backend.
func ConformBackend(b Backend, algorithms []Algorithm) error {
	if b == nil {
		return fmt.Errorf("crypto: ConformBackend: nil backend")
	}
	if b.Name() == "" {
		return fmt.Errorf("crypto: ConformBackend: backend reports no name")
	}
	if len(algorithms) == 0 {
		return fmt.Errorf("crypto: ConformBackend: no algorithms to exercise")
	}
	for _, alg := range algorithms {
		if err := conformOne(b, alg); err != nil {
			return fmt.Errorf("crypto: backend %q failed conformance for %s: %w", b.Name(), alg, err)
		}
	}
	return nil
}

func conformOne(b Backend, alg Algorithm) error {
	signer, err := b.GenerateKey(alg)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	if got := signer.Algorithm(); got != alg {
		return fmt.Errorf("signer reports algorithm %q, want %q", got, alg)
	}
	pub := signer.Public()
	if len(pub.DER) == 0 {
		return fmt.Errorf("signer returned an empty public key")
	}
	opts := SignOptions{Hash: SHA256}
	msg := []byte("trstctl backend conformance probe")
	sig, err := signer.Sign(msg, opts)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if err := Verify(pub, msg, sig, opts); err != nil {
		return fmt.Errorf("signature did not verify against the returned public key: %w", err)
	}
	if err := Verify(pub, []byte("a different message"), sig, opts); err == nil {
		return fmt.Errorf("a signature verified against the wrong message (not fail-closed)")
	}
	if len(sig) > 0 {
		tampered := bytes.Clone(sig)
		tampered[len(tampered)-1] ^= 0xff
		if err := Verify(pub, msg, tampered, opts); err == nil {
			return fmt.Errorf("a tampered signature verified (not fail-closed)")
		}
	}
	return nil
}
