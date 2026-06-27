package crypto

import (
	"crypto/fips140"
	"errors"
	"fmt"
)

// This file is the FIPS posture surface of the AN-3 boundary (PKIGOV-007 /
// EXC-CRYPTO-01). Because crypto/fips140 is itself a crypto/* package, the AN-3
// linter forbids importing it anywhere outside internal/crypto — so the FIPS
// state of the process is read and asserted ONLY here, and the rest of the tree
// (cmd/trstctl, the signer, the orchestrator) reaches it through these
// boundary-agnostic functions rather than importing crypto/fips140 itself.
//
// What "FIPS-capable" means here, precisely. Go 1.24+ ships a FIPS 140-3 Go
// Cryptographic Module: building with GOFIPS140=latest (or running any build with
// GODEBUG=fips140=on) routes the standard library's crypto/* through that
// validated module and makes fips140.Enabled() report true. trstctl's whole
// crypto surface enters through this one package (AN-3), so when the module is
// active every signature, hash, and AEAD trstctl performs runs inside it.
//
// This is FIPS-*capable*: it uses the Go Cryptographic Module, which has a CMVP
// validation. The trstctl *product's* own NIST CMVP certificate is a separate,
// external process (a lab test + certificate issuance) that code cannot perform;
// it is the named residual of EXC-CRYPTO-01. Two further caveats the POST cannot
// erase: the post-quantum schemes (ML-DSA/ML-KEM/SLH-DSA via CIRCL) are not in
// the module's boundary, and a key custodied in an external HSM/KMS is validated
// by that device, not by this module.

// ErrFIPSRequiredButInactive is returned by the power-on self-test when the
// operator requires FIPS mode (a --fips assert / config flag) but the running
// binary's crypto is NOT routed through the FIPS module — i.e. it was not built
// with GOFIPS140 and GODEBUG=fips140=on was not set. It is the fail-closed signal:
// a deployment that must be FIPS-validated refuses to start in a non-FIPS build
// rather than silently issuing credentials with an unvalidated module.
var ErrFIPSRequiredButInactive = errors.New("crypto: FIPS mode required but the FIPS cryptographic module is not active (build with GOFIPS140=latest or run with GODEBUG=fips140=on)")

// ErrSelfTestFailed is returned when the boundary's known-answer self-test does
// not reproduce — a sign/verify round-trip through the live backend fails. It
// means the cryptographic primitives this process will use are not behaving, so
// the process must not proceed to issue or protect credentials with them.
var ErrSelfTestFailed = errors.New("crypto: cryptographic self-test failed")

// FIPSEnabled reports whether the FIPS 140-3 Go Cryptographic Module is active
// for this process. It is true when the binary was built with GOFIPS140 (e.g.
// `make fips-build`) or is run with GODEBUG=fips140=on, and false otherwise. It
// is the single read of crypto/fips140.Enabled() in the tree (AN-3).
func FIPSEnabled() bool { return fips140.Enabled() }

// FIPSStatus is a boundary-agnostic snapshot of the process's FIPS posture, for
// --check-config / startup diagnostics. It exposes no crypto/* types so callers
// outside the boundary can print it without importing crypto/fips140 (AN-3).
type FIPSStatus struct {
	// ModuleActive is true when the FIPS 140-3 module is routing crypto/*.
	ModuleActive bool `json:"module_active"`
	// Required is the operator's assertion (the --fips flag / config) that the
	// process must run with the FIPS module active.
	Required bool `json:"required"`
	// SelfTestPassed reports whether the power-on known-answer self-test passed.
	SelfTestPassed bool `json:"self_test_passed"`
}

// Summary renders the FIPS posture as a single human-readable line for the
// startup banner and --check-config.
func (s FIPSStatus) Summary() string {
	mode := "FIPS module: inactive (standard crypto/*)"
	if s.ModuleActive {
		mode = "FIPS module: ACTIVE (Go FIPS 140-3 Cryptographic Module)"
	}
	req := "not required"
	if s.Required {
		req = "REQUIRED"
	}
	st := "self-test FAILED"
	if s.SelfTestPassed {
		st = "self-test passed"
	}
	return fmt.Sprintf("%s; %s; %s", mode, req, st)
}

// PowerOnSelfTest is the cryptographic power-on self-test (POST) trstctl runs at
// startup, before it serves any request (EXC-CRYPTO-01). It does two things:
//
//  1. Always runs a known-answer self-test of the boundary: it generates a key,
//     signs a fixed probe, and verifies the signature, asserting both that a good
//     signature verifies and that a tampered one is rejected (fail-closed). This
//     exercises the live signing/verification path the running binary will use —
//     under the FIPS module when one is active, under the standard library when
//     not — so a broken or mis-linked crypto stack is caught at boot, not on the
//     first issuance. (The Go FIPS module additionally runs its own CASTs the
//     first time it is used; this is trstctl's own end-to-end check on top.)
//
//  2. If required is true (the operator asserted --fips / fips.required), it
//     additionally asserts the FIPS module is active and FAILS CLOSED with
//     ErrFIPSRequiredButInactive when it is not. This is the regulated-deployment
//     guard: a binary that must be FIPS-validated will not boot in a non-FIPS
//     build, so it can never silently fall back to an unvalidated module.
//
// It returns the resolved FIPSStatus alongside any error so the caller can log
// the posture even on the success path. On any error the process must not start.
func PowerOnSelfTest(required bool) (FIPSStatus, error) {
	status := FIPSStatus{ModuleActive: FIPSEnabled(), Required: required}

	if err := selfTestKAT(); err != nil {
		return status, err
	}
	status.SelfTestPassed = true

	if required && !status.ModuleActive {
		return status, ErrFIPSRequiredButInactive
	}
	return status, nil
}

// selfTestKAT runs the boundary's known-answer self-test: a sign→verify→reject
// round-trip with the default software backend over a fixed probe. It asserts a
// valid signature verifies, a wrong message does not, and a tampered signature
// does not — proving the live primitives fail closed. It uses ECDSA-P256/SHA-256,
// which is in both the standard library and the FIPS module's boundary, so the
// same test is meaningful in either mode. It is reused by the FIPS regression
// guard so a future change that breaks this path is caught.
func selfTestKAT() error {
	const algo = ECDSAP256
	signer, err := NewSoftwareBackend().GenerateKey(algo)
	if err != nil {
		return fmt.Errorf("%w: generate %s: %v", ErrSelfTestFailed, algo, err)
	}
	opts := SignOptions{Hash: SHA256}
	probe := []byte("trstctl FIPS power-on self-test probe")
	sig, err := signer.Sign(probe, opts)
	if err != nil {
		return fmt.Errorf("%w: sign: %v", ErrSelfTestFailed, err)
	}
	pub := signer.Public()
	if err := Verify(pub, probe, sig, opts); err != nil {
		return fmt.Errorf("%w: a good signature did not verify: %v", ErrSelfTestFailed, err)
	}
	if err := Verify(pub, []byte("a different message"), sig, opts); err == nil {
		return fmt.Errorf("%w: a signature verified over the wrong message (not fail-closed)", ErrSelfTestFailed)
	}
	if len(sig) > 0 {
		tampered := make([]byte, len(sig))
		copy(tampered, sig)
		tampered[len(tampered)-1] ^= 0xff
		if err := Verify(pub, probe, tampered, opts); err == nil {
			return fmt.Errorf("%w: a tampered signature verified (not fail-closed)", ErrSelfTestFailed)
		}
	}
	return nil
}
