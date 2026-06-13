package crypto

import (
	"bytes"
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
	msg := []byte("trustctl backend conformance probe")
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
