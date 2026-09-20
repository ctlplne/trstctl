// SPDX-License-Identifier: BUSL-1.1

package crypto

import "context"

// Algorithm identifies a key and signature algorithm.
type Algorithm string

// Classical (quantum-vulnerable) signature algorithms.
const (
	RSA2048   Algorithm = "RSA-2048"
	RSA3072   Algorithm = "RSA-3072"
	RSA4096   Algorithm = "RSA-4096"
	ECDSAP256 Algorithm = "ECDSA-P256"
	ECDSAP384 Algorithm = "ECDSA-P384"
	ECDSAP521 Algorithm = "ECDSA-P521"
	Ed25519   Algorithm = "Ed25519"
)

// Hash identifies a message digest algorithm.
type Hash string

// Supported hashes.
const (
	SHA256 Hash = "SHA-256"
	SHA384 Hash = "SHA-384"
	SHA512 Hash = "SHA-512"
)

// RSAPadding selects the RSA signature scheme. It is ignored for non-RSA keys.
type RSAPadding string

// RSA signature schemes.
const (
	RSAPKCS1v15 RSAPadding = "PKCS1v15"
	RSAPSS      RSAPadding = "PSS"
)

// SignOptions controls a signing or verification operation.
type SignOptions struct {
	Hash       Hash       // digest algorithm; defaults to SHA-256 when empty
	RSAPadding RSAPadding // RSA scheme; defaults to PKCS#1 v1.5 when empty
}

// CertificateExtension is a backend-agnostic X.509 extension. OID is a dotted
// object identifier, Critical is the X.509 critical bit, and Value is the DER
// encoded extension value. It lets callers inside the crypto boundary assemble
// draft/profile extensions without leaking crypto/x509/pkix types outward.
type CertificateExtension struct {
	OID      string
	Critical bool
	Value    []byte
}

// PublicKey is a backend-agnostic public key: its algorithm plus the PKIX/DER
// (SubjectPublicKeyInfo) encoding. It deliberately exposes no standard-library
// crypto types so callers never need to import crypto/* (AN-3).
type PublicKey struct {
	Algorithm Algorithm
	DER       []byte
}

// Signer holds a private key and signs with it. The private key never leaves
// the backend; callers hold only this handle.
type Signer interface {
	// Public returns the corresponding public key.
	Public() PublicKey
	// Algorithm reports the key's algorithm.
	Algorithm() Algorithm
	// Sign hashes message per opts and returns the signature.
	Sign(message []byte, opts SignOptions) (signature []byte, err error)
}

// KeyGenerator creates new keys. Backends (software, HSM, KMS, or licensed
// extensions) implement it; swapping one backend for another requires no caller
// changes.
type KeyGenerator interface {
	GenerateKey(algorithm Algorithm) (Signer, error)
}

// ContextSigner is a Signer whose signing operation accepts a context.Context, so
// a caller can cancel or deadline-bound the operation (CODE-002). It exists for
// backends whose Sign is a remote network call — a cloud KMS or a networked HSM —
// where a hung endpoint would otherwise block the calling goroutine indefinitely,
// defeating AN-7 backpressure for the slowest possible operation (a remote crypto
// call). The CPU-bound software signer does not implement it (it genuinely needs
// no context); callers detect support with a type assertion or use SignContext.
type ContextSigner interface {
	Signer
	// SignContext hashes message per opts and returns the signature, honoring
	// the context's cancellation/deadline. Backends that reach the network MUST
	// propagate ctx into the request so a caller deadline bounds the call.
	SignContext(ctx context.Context, message []byte, opts SignOptions) (signature []byte, err error)
}

// ContextKeyGenerator is a KeyGenerator whose key creation accepts a
// context.Context (CODE-002). Like ContextSigner it exists for backends that
// reach the network during key generation (a cloud KMS CreateKey/GetPublicKey
// round-trip), so the caller can cancel or deadline-bound them.
type ContextKeyGenerator interface {
	KeyGenerator
	// GenerateKeyContext creates a key, honoring the context's
	// cancellation/deadline. Network backends MUST propagate ctx into every
	// request the generation makes.
	GenerateKeyContext(ctx context.Context, algorithm Algorithm) (Signer, error)
}

// SignContext signs message with s, threading ctx when s supports it
// (ContextSigner) and falling back to the context-less Sign otherwise. It is the
// canonical way to drive a signer when the caller holds a context: a remote KMS
// signer gets a real, cancelable, deadline-bound call; the CPU-bound software
// signer is unaffected. The context is honored only as far as the concrete
// backend propagates it — for the in-process software signer there is no I/O to
// cancel, so it returns its (immediate) result.
func SignContext(ctx context.Context, s Signer, message []byte, opts SignOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cs, ok := s.(ContextSigner); ok {
		return cs.SignContext(ctx, message, opts)
	}
	return s.Sign(message, opts)
}

// GenerateKeyContext creates a key with g, threading ctx when g supports it
// (ContextKeyGenerator) and falling back to the context-less GenerateKey
// otherwise. A networked backend (cloud KMS) gets a cancelable, deadline-bound
// generation; the software backend is unaffected.
func GenerateKeyContext(ctx context.Context, g KeyGenerator, algorithm Algorithm) (Signer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cg, ok := g.(ContextKeyGenerator); ok {
		return cg.GenerateKeyContext(ctx, algorithm)
	}
	return g.GenerateKey(algorithm)
}

// DigestSigner signs a pre-computed digest. This is the canonical signing
// operation for X.509/CSR and certificate signing and for HSMs, and it is
// implemented by both in-process keys (LockedSigner) and remote keys (the
// signing service client), so the same code can drive either.
type DigestSigner interface {
	Public() PublicKey
	Algorithm() Algorithm
	SignDigest(digest []byte, opts SignOptions) (signature []byte, err error)
}
