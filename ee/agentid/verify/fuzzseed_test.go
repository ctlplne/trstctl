// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/ee/agentid/delegation/carriage"
	"trstctl.com/trstctl/internal/crypto"
)

// jsonMarshalJWKS marshals a single-key JWKS to JSON for the fuzz seeds.
func jsonMarshalJWKS(jwk crypto.JWK) ([]byte, error) {
	return json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
}

// fuzzseed_test.go builds valid seeds for the fuzz targets using *testing.F (a
// testing.TB), so a genuine credential anchors the fuzzer's search.

func buildReprFuzzSeed(tools []string) []byte {
	var b bytes.Buffer
	writeS := func(s string) {
		var x [8]byte
		binary.BigEndian.PutUint64(x[:], uint64(len(s)))
		b.Write(x[:])
		b.WriteString(s)
	}
	writeB := func(p []byte) {
		var x [8]byte
		binary.BigEndian.PutUint64(x[:], uint64(len(p)))
		b.Write(x[:])
		b.Write(p)
	}
	b.WriteString(reprCanonicalPrefix)
	writeS("system_prompt_digest")
	writeB(crypto.SHA256Sum([]byte("seed-prompt")))
	writeS("tool_manifest_digest")
	writeB(toolManifestDigest(tools))
	writeS("model")
	b.WriteByte(byte(modelFormProviderID))
	writeS("provider_model_id")
	writeS("anthropic/claude-x")
	writeS("model_version")
	writeS("2026-01-01")
	writeS("orchestrator")
	writeS("o")
	writeS("runtime")
	writeS("r")
	return b.Bytes()
}

func seedRepr(f *testing.F) []byte {
	f.Helper()
	return buildReprFuzzSeed([]string{"read-object", "list-bucket"})
}

func seedReprDigest(f *testing.F) []byte {
	f.Helper()
	return reprDigest(seedRepr(f))
}

// seedIssuer builds a fixed issuer + JWKS shared by the token seeds.
func seedIssuer(f *testing.F) (*crypto.LockedSigner, []byte) {
	f.Helper()
	issuer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		f.Fatalf("issuer: %v", err)
	}
	f.Cleanup(issuer.Destroy)
	jwk, err := crypto.PublicJWK(issuer.Public(), "kid-seed")
	if err != nil {
		f.Fatalf("jwk: %v", err)
	}
	b, err := jsonMarshalJWKS(jwk)
	if err != nil {
		f.Fatalf("jwks: %v", err)
	}
	return issuer, b
}

var fuzzSeedIssuer *crypto.LockedSigner
var fuzzSeedJWKS []byte

func seedJWKS(f *testing.F) []byte {
	f.Helper()
	if fuzzSeedJWKS == nil {
		fuzzSeedIssuer, fuzzSeedJWKS = seedIssuer(f)
	}
	return fuzzSeedJWKS
}

func buildValidTokenSeed(f *testing.F) []byte {
	f.Helper()
	if fuzzSeedJWKS == nil {
		fuzzSeedIssuer, fuzzSeedJWKS = seedIssuer(f)
	}
	repr := seedRepr(f)
	bv := carriage.BoundValues{
		AgentStackDigest:  reprDigest(repr),
		AgentStackRepr:    repr,
		DesignatedClass:   "reader",
		ComparatorVersion: "v1",
	}
	tok, err := carriage.EncodeSignedToken(fuzzSeedIssuer, "kid-seed", bv, "spiffe://agent", "aud", "iss")
	if err != nil {
		f.Fatalf("EncodeSignedToken: %v", err)
	}
	return []byte(tok)
}
