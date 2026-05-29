// Package pqc implements post-quantum and hybrid signatures behind the AN-3
// boundary. It is the only package that imports the post-quantum crypto library
// (github.com/cloudflare/circl), so callers — including the sacred signer —
// link that dependency only if they explicitly use this package, keeping their
// dependency surface minimal.
//
// FIPS-build caveat: CIRCL's ML-DSA / Dilithium implementations are not part of
// a FIPS 140-3 validated cryptographic module. In a FIPS build these algorithms
// may be unavailable or must be supplied by the validated module; PQC FIPS
// validation across the ecosystem is still maturing. Treat this package as
// non-FIPS until a validated post-quantum module is wired in.
package pqc
