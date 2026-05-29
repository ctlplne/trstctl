package crypto

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
)

// Post-quantum and hybrid algorithms. The signing implementations live behind
// the boundary in internal/crypto/pqc (which is the only place the PQC library
// is imported); these constants are usable for selection and inventory
// classification without pulling that dependency into callers.
const (
	// ML-DSA (FIPS 204) signature algorithms.
	MLDSA44 Algorithm = "ML-DSA-44"
	MLDSA65 Algorithm = "ML-DSA-65"
	MLDSA87 Algorithm = "ML-DSA-87"

	// ML-KEM (FIPS 203) key-encapsulation mechanisms. These are not signature
	// schemes; they are modeled here for inventory classification.
	MLKEM512  Algorithm = "ML-KEM-512"
	MLKEM768  Algorithm = "ML-KEM-768"
	MLKEM1024 Algorithm = "ML-KEM-1024"

	// HybridEd25519Dilithium3 is a hybrid signature combining classical Ed25519
	// with post-quantum Dilithium (mode 3): a forgery requires breaking both.
	HybridEd25519Dilithium3 Algorithm = "Hybrid-Ed25519-Dilithium3"
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

// KeyGenerator creates new keys. Backends (software, HSM, KMS, post-quantum,
// ...) implement it; swapping one backend for another requires no caller
// changes.
type KeyGenerator interface {
	GenerateKey(algorithm Algorithm) (Signer, error)
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
