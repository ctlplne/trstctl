package crypto

// Algorithm identifies a key and signature algorithm.
type Algorithm string

// Supported algorithms.
const (
	RSA2048   Algorithm = "RSA-2048"
	RSA3072   Algorithm = "RSA-3072"
	RSA4096   Algorithm = "RSA-4096"
	ECDSAP256 Algorithm = "ECDSA-P256"
	ECDSAP384 Algorithm = "ECDSA-P384"
	ECDSAP521 Algorithm = "ECDSA-P521"
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
