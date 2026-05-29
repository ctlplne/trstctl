// Package crypto is the AN-3 cryptography boundary: the single package in the
// tree permitted to import the standard library's crypto/* packages.
//
// It defines backend-agnostic types and interfaces — Algorithm, Hash,
// PublicKey, SignOptions, Signer, and KeyGenerator — behind which concrete
// backends plug in. Callers depend only on these types and never import a
// standard-library crypto package, so adding an algorithm or a hardware backend
// is a single-package change. The architecture linter (tools/certctllint)
// enforces that no crypto/* import appears anywhere else.
//
// The SoftwareBackend implements RSA and ECDSA with the Go standard library;
// HSM, KMS, and post-quantum backends follow in later sprints. Memory-safe key
// buffers (AN-8) are layered on in S1.2.
package crypto
