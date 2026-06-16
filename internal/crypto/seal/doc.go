// Package seal provides envelope encryption for credentials at rest (R3.1).
//
// A fresh random data-encryption key (DEK) encrypts each credential with
// AES-256-GCM (bound to caller-supplied associated data), and a key-encryption
// key (KEK) wraps the DEK. Only wrapped DEKs and ciphertext are ever stored, so
// the at-rest representation is opaque and integrity-protected. The KEK is
// reached through the KeyWrapper interface: a local key (LocalKEK) today, an
// HSM/KMS tomorrow — the wrapper never exposes the KEK to callers.
//
// This is part of the cryptography boundary (AN-3) and handles raw key material,
// so the package is marked key-handling: the AN-8 linter forbids any string-typed
// field, parameter, or result here — keys and secrets live in []byte that can be
// locked, dump-protected, and zeroized.
package seal

//trstctl:keymaterial
