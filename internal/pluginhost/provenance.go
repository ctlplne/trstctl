package pluginhost

import (
	"context"
	"encoding/hex"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// TrustPolicy is the operator-configured provenance policy a WASM module must
// satisfy before the host will instantiate it (SUPPLY-004). The host's stated
// purpose is loading code the core team did not write, so admitting an
// unverified `.wasm` is a supply-chain vector even with the sandbox; this gate
// closes it.
//
// A module is admitted only if BOTH hold:
//
//   - its detached signature verifies under one of TrustedKeys (an Ed25519
//     signature over the exact module bytes, checked through internal/crypto so
//     no crypto/* import lands here — AN-3); and
//   - when PinnedDigests is non-empty, the module's SHA-256 is one of the pinned
//     digests (content pinning, so an operator can additionally require an exact
//     known-good artifact).
//
// The zero value is FAIL-CLOSED: with no trusted keys, Verify rejects every
// module. The sandbox remains defense-in-depth — provenance does not relax it.
type TrustPolicy struct {
	// trustedKeys are the PKIX/DER Ed25519 public keys whose signature over a
	// module admits it. At least one is required (an empty set rejects all).
	trustedKeys [][]byte
	// pinnedDigests, when non-empty, additionally restricts admitted modules to
	// those whose lowercase-hex SHA-256 is listed (content pinning). Empty means
	// "any module a trusted key signed".
	pinnedDigests map[string]bool
}

// NewTrustPolicy builds a TrustPolicy from PEM-encoded Ed25519 public keys and
// an optional set of pinned content digests (lowercase hex SHA-256 of the
// `.wasm`). It returns an error if no usable trusted key is supplied or a key /
// digest is malformed — an operator that asks for a verified plugin surface but
// configures no key gets a startup error, not a silently-open host.
func NewTrustPolicy(trustedKeyPEMs [][]byte, pinnedDigestsHex []string) (*TrustPolicy, error) {
	tp := &TrustPolicy{pinnedDigests: map[string]bool{}}
	for i, pemBytes := range trustedKeyPEMs {
		der, err := crypto.ParseEd25519PublicKeyPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("pluginhost: trusted key %d: %w", i, err)
		}
		tp.trustedKeys = append(tp.trustedKeys, der)
	}
	if len(tp.trustedKeys) == 0 {
		return nil, fmt.Errorf("pluginhost: trust policy requires at least one trusted Ed25519 public key (fail closed)")
	}
	for _, d := range pinnedDigestsHex {
		raw, err := hex.DecodeString(d)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("pluginhost: pinned digest %q is not a 32-byte hex SHA-256", d)
		}
		tp.pinnedDigests[normalizeHex(d)] = true
	}
	return tp, nil
}

// Verify reports whether wasm is admitted under the policy: a valid detached
// Ed25519 signature from a trusted key over the exact module bytes, and (if any
// digests are pinned) a matching content digest. It fails closed — any failure
// (no trusted key, bad signature, unpinned digest) returns a non-nil error and
// the module must not run.
func (tp *TrustPolicy) Verify(wasm, signature []byte) error {
	if tp == nil || len(tp.trustedKeys) == 0 {
		return fmt.Errorf("pluginhost: no plugin trust policy configured; refusing to load unverified module (fail closed)")
	}
	if len(signature) == 0 {
		return fmt.Errorf("pluginhost: module has no provenance signature; refusing to load (SUPPLY-004)")
	}
	// Content pin (when configured) before signature, so a tampered/unknown
	// artifact is rejected even if it were somehow signed. The match is
	// constant-time per candidate so digest comparison does not leak via timing.
	if len(tp.pinnedDigests) > 0 {
		got := normalizeHex(crypto.SHA256Hex(wasm))
		matched := false
		for want := range tp.pinnedDigests {
			if crypto.ConstantTimeEqual([]byte(got), []byte(want)) {
				matched = true
			}
		}
		if !matched {
			return fmt.Errorf("pluginhost: module digest %s is not in the pinned allowlist (SUPPLY-004)", got)
		}
	}
	// A signature from ANY configured trusted key admits the module.
	for _, der := range tp.trustedKeys {
		if err := crypto.VerifyEd25519(der, wasm, signature); err == nil {
			return nil
		}
	}
	return fmt.Errorf("pluginhost: module signature does not verify under any trusted key; refusing to load (SUPPLY-004)")
}

// LoadVerified is the only admission path a SERVED plugin surface uses: it
// verifies the module's provenance against tp BEFORE instantiating anything,
// then loads it under grant exactly as Load does. A module that is unsigned, was
// signed by an untrusted key, was tampered after signing, or is not in the
// pinned allowlist is REFUSED — the runtime is never even created for it. The
// wazero sandbox still applies as defense-in-depth (AN-7 bulkhead, no ambient
// capabilities, grant-gated host funcs); provenance is the layer that decides
// whether code the core team did not write is allowed to execute at all.
func (h *Host) LoadVerified(ctx context.Context, wasm, signature []byte, tp *TrustPolicy, grant Grant) (*Plugin, error) {
	if err := tp.Verify(wasm, signature); err != nil {
		return nil, err
	}
	return h.Load(ctx, wasm, grant)
}

// normalizeHex lowercases a hex digest so pin comparison does not depend on the
// casing an operator wrote the digest in.
func normalizeHex(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'F' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
