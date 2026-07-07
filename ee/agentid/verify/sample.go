// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"encoding/binary"
	"encoding/json"

	"trstctl.com/trstctl/ee/agentid/delegation/carriage"
	"trstctl.com/trstctl/internal/crypto"
)

// sample.go builds a self-contained, deterministic-shape sample credential and its
// matching policy/action, so the WASM entrypoint (./wasm) and the native parity
// test evaluate the EXACT same offline case and must agree (native/WASM parity,
// AGID-09 WASM smoke test). It uses only the WASM-safe crypto boundary (software
// backend, token signing) and the carriage encoders, so it links and runs under
// GOOS=js GOARCH=wasm. It performs a key operation only to MINT the sample
// credential for the demo; the verify path it exercises holds no key.

// SampleResult is the compact, comparable outcome of verifying the sample
// credential. Both native and WASM print it; the parity test asserts equality.
type SampleResult struct {
	Accepted     bool
	AuthClass    string
	Operation    string
	Tool         string
	RefusalError string
}

// BuildAndVerifySample builds the sample signed-token credential (a valid,
// in-policy, in-authority, in-tool-manifest, unexpired case), verifies it offline,
// and returns the comparable result. It is deterministic in DECISION (accept) even
// though the signing key is random, because the policy is derived from the same
// representation/manifest that is bound. Returns a zero SampleResult and false only
// on an internal build error (never expected).
func BuildAndVerifySample() (SampleResult, bool) {
	// Issuer key (a DigestSigner, for signing the token) + a pinned JWKS trust root
	// (offline). GenerateLockedKey keeps the private key in a locked, zeroizable
	// buffer (AN-8); it is destroyed before we return.
	issuer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return SampleResult{}, false
	}
	defer issuer.Destroy()
	jwks, err := jwksForKey(issuer.Public(), "sample-kid")
	if err != nil {
		return SampleResult{}, false
	}

	// The bound agent-stack representation (opaque canonical bytes) and its digest,
	// with a known tool manifest. We build the canonical bytes directly in the AGID-03
	// framing so the sample stays free of the agentstack package (WASM-lean), matching
	// how the verifier recovers them.
	tools := []string{"read-object", "list-bucket"}
	repr := sampleRepr(tools)
	reprDig := reprDigest(repr)

	bv := carriage.BoundValues{
		AgentStackDigest:  reprDig,
		AgentStackRepr:    repr,
		DesignatedClass:   "reader",
		ComparatorVersion: "v1",
	}

	token, err := carriage.EncodeSignedToken(issuer, "sample-kid", bv, "spiffe://agent", "aud", "iss")
	if err != nil {
		return SampleResult{}, false
	}

	policy := NewLocalPolicy().
		ApproveAgentStack(reprDig).
		PermitClass("reader").
		GrantOperations("reader", "read-object").
		WithToolManifest(tools...)

	action := Action{Operation: "read-object", Tool: "read-object"}

	res, verr := Verify(
		Credential{Form: FormSignedToken, Bytes: []byte(token)},
		TrustRoot{JWKSJSON: jwks},
		policy,
		action,
		FixedClock(unixToTime(1_000_000)),
	)
	if verr != nil {
		return SampleResult{Accepted: false, RefusalError: verr.Error()}, true
	}
	return SampleResult{
		Accepted:  true,
		AuthClass: res.AuthorityClass,
		Operation: res.Operation,
		Tool:      res.Tool,
	}, true
}

// sampleRepr builds the AGID-03 canonical agent-stack representation bytes for a
// fixed prompt/model and the given tool manifest, in the exact framing
// decodeBoundRepr accepts. It mirrors agentstack.Representation.CanonicalBytes for
// a provider-id model, without importing agentstack.
func sampleRepr(tools []string) []byte {
	var b []byte
	appendStr := func(s string) {
		var x [8]byte
		putU64(x[:], uint64(len(s)))
		b = append(b, x[:]...)
		b = append(b, s...)
	}
	appendBytes := func(p []byte) {
		var x [8]byte
		putU64(x[:], uint64(len(p)))
		b = append(b, x[:]...)
		b = append(b, p...)
	}
	b = append(b, reprCanonicalPrefix...)
	appendStr("system_prompt_digest")
	appendBytes(crypto.SHA256Sum([]byte("sample-system-prompt")))
	appendStr("tool_manifest_digest")
	appendBytes(toolManifestDigest(tools))
	appendStr("model")
	b = append(b, byte(modelFormProviderID))
	appendStr("provider_model_id")
	appendStr("anthropic/claude-x")
	appendStr("model_version")
	appendStr("2026-01-01")
	appendStr("orchestrator")
	appendStr("orch-1")
	appendStr("runtime")
	appendStr("rt-1")
	return b
}

// jwksForKey builds a static JWKS JSON (a single verifying key, by kid) from a
// public key, entirely through the crypto boundary (crypto.PublicJWK). The relying
// party pins this out of band; the verifier NEVER fetches a jwks_uri.
func jwksForKey(pub crypto.PublicKey, kid string) ([]byte, error) {
	jwk, err := crypto.PublicJWK(pub, kid)
	if err != nil {
		return nil, err
	}
	return json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
}

// putU64 writes a big-endian uint64 into an 8-byte slice, mirroring the canonical
// framing writers so sampleRepr frames bytes exactly as agentstack does.
func putU64(dst []byte, v uint64) { binary.BigEndian.PutUint64(dst, v) }
