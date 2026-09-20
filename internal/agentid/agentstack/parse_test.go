// SPDX-License-Identifier: BUSL-1.1

package agentstack_test

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/agentid/agentstack"
	"trstctl.com/trstctl/internal/attest"
)

// TestParse_RoundTrip confirms a valid representation round-trips through
// CanonicalBytes -> Parse for both model forms, and that Parse fails closed on
// truncation, trailing bytes, and a bad prefix.
func TestParse_RoundTrip(t *testing.T) {
	build := func(t *testing.T, m agentstack.Model) agentstack.Representation {
		t.Helper()
		rep, err := agentstack.New([]byte("prompt"), agentstack.NewToolManifest("fs.read", "net.http"), m)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		rep.Orchestrator = "orch/1"
		rep.Runtime = "rt/2"
		return rep
	}

	for _, m := range []agentstack.Model{
		{Form: agentstack.ModelFormProviderID, ProviderModelID: "prov/model", ModelVersion: "v1"},
		{Form: agentstack.ModelFormWeightsDigest, WeightsDigest: bytes.Repeat([]byte{0xab}, 32)},
	} {
		rep := build(t, m)
		cb, err := rep.CanonicalBytes()
		if err != nil {
			t.Fatalf("CanonicalBytes: %v", err)
		}
		got, err := agentstack.Parse(cb)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		// Re-encode the parsed representation; the bytes must match exactly.
		reCB, err := got.CanonicalBytes()
		if err != nil {
			t.Fatalf("re-CanonicalBytes: %v", err)
		}
		if !bytes.Equal(cb, reCB) {
			t.Fatalf("round-trip mismatch for form %v", m.Form)
		}

		// Truncation fails closed.
		if _, err := agentstack.Parse(cb[:len(cb)-1]); err == nil {
			t.Error("Parse accepted truncated bytes; want error")
		}
		// Trailing bytes fail closed.
		if _, err := agentstack.Parse(append(append([]byte(nil), cb...), 0x00)); err == nil {
			t.Error("Parse accepted trailing bytes; want error")
		}
	}

	// A bad/empty prefix fails closed.
	if _, err := agentstack.Parse([]byte("not the prefix at all")); err == nil {
		t.Error("Parse accepted a bad prefix; want error")
	}
	if _, err := agentstack.Parse(nil); err == nil {
		t.Error("Parse accepted nil; want error")
	}
}

// TestAttestationDigest_StableAndReadOnly confirms the environment-attestation
// digest (read-only consumption of internal/attest) is stable regardless of
// selector/claim ordering and flips on any content change. It also confirms the
// input Attestation is not mutated (read-only, §1.6 zero-removal).
func TestAttestationDigest_StableAndReadOnly(t *testing.T) {
	att := attest.Attestation{
		ID:        "att:abc",
		Method:    "tpm",
		Subject:   "instance-1",
		Selectors: []string{"b", "a", "c"},
		Claims:    map[string]string{"z": "1", "a": "2"},
	}
	d1 := agentstack.AttestationDigest(att)
	if len(d1) != 32 {
		t.Fatalf("attestation digest = %d bytes, want 32", len(d1))
	}

	// Re-ordered selectors + a freshly-built (differently-iterating) claims map
	// yield the same digest.
	att2 := attest.Attestation{
		ID:        "att:abc",
		Method:    "tpm",
		Subject:   "instance-1",
		Selectors: []string{"c", "a", "b"},
		Claims:    map[string]string{"a": "2", "z": "1"},
	}
	if !bytes.Equal(d1, agentstack.AttestationDigest(att2)) {
		t.Error("attestation digest is not order-independent over selectors/claims")
	}

	// A content change flips the digest.
	att3 := att
	att3.Subject = "instance-2"
	if bytes.Equal(d1, agentstack.AttestationDigest(att3)) {
		t.Error("changing the attested subject did not flip the digest")
	}

	// The input must not have been mutated (read-only).
	if att.Selectors[0] != "b" || att.Selectors[1] != "a" || att.Selectors[2] != "c" {
		t.Error("AttestationDigest mutated the input attestation's selectors (must be read-only)")
	}
}

// FuzzParse drives arbitrary, untrusted bytes through the representation parser.
// The contract is that Parse never panics and either returns a valid, re-
// encodable representation or an error — no partial/ambiguous state escapes.
